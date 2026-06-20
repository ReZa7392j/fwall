#!/usr/bin/env python3
"""
fwall — Simple Linux Firewall (fwall.py)
Single-file core: CLI + rule model + state + logger + engine bridge.
Must be run as root.
"""

import argparse
import configparser
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────
# Paths
# ─────────────────────────────────────────

CONF_FILE   = Path("/etc/fwall/fwall.conf")
RULES_FILE  = Path("/etc/fwall/rules.json")
LOG_FILE    = Path("/var/log/fwall.log")
ENGINE_SH   = Path("/usr/local/lib/fwall/engine.sh")

# ─────────────────────────────────────────
# Config loader
# ─────────────────────────────────────────

def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "policy":  {"default_incoming": "deny", "default_outgoing": "allow"},
        "logging": {"enabled": "true", "level": "info", "path": str(LOG_FILE)},
        "engine":  {"backend": "iptables"},
    })
    if CONF_FILE.exists():
        cfg.read(CONF_FILE)
    return cfg

# ─────────────────────────────────────────
# Logger
# ─────────────────────────────────────────

def setup_logger(cfg: configparser.ConfigParser) -> logging.Logger:
    logger = logging.getLogger("fwall")
    enabled = cfg.getboolean("logging", "enabled", fallback=True)
    level_str = cfg.get("logging", "level", fallback="info").upper()
    log_path = cfg.get("logging", "path", fallback=str(LOG_FILE))

    if not enabled:
        logger.addHandler(logging.NullHandler())
        return logger

    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("[fwall] %(levelname)s: %(message)s"))
    logger.addHandler(ch)

    # File handler
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path)
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [fwall] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    except PermissionError:
        logger.warning(f"Cannot write to log file {log_path} — file logging disabled.")

    return logger

# ─────────────────────────────────────────
# Rule model
# ─────────────────────────────────────────

class Rule:
    VALID_ACTIONS    = {"allow", "deny"}
    VALID_PROTOS     = {"tcp", "udp", "any"}
    VALID_DIRECTIONS = {"in", "out"}

    def __init__(self, action, proto="tcp", port="any",
                 direction="in", from_ip="any", to_ip="any", rule_id=None):
        self.id        = rule_id
        self.action    = action.lower()
        self.proto     = proto.lower()
        self.port      = str(port)
        self.direction = direction.lower()
        self.from_ip   = from_ip or "any"
        self.to_ip     = to_ip or "any"
        self._validate()

    def _validate(self):
        if self.action not in self.VALID_ACTIONS:
            raise ValueError(f"Invalid action '{self.action}'. Use: allow, deny")
        if self.proto not in self.VALID_PROTOS:
            raise ValueError(f"Invalid protocol '{self.proto}'. Use: tcp, udp, any")
        if self.direction not in self.VALID_DIRECTIONS:
            raise ValueError(f"Invalid direction '{self.direction}'. Use: in, out")
        if self.port != "any":
            try:
                p = int(self.port)
                if not (1 <= p <= 65535):
                    raise ValueError()
            except ValueError:
                raise ValueError(f"Invalid port '{self.port}'. Use 1-65535 or 'any'")

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "action":    self.action,
            "proto":     self.proto,
            "port":      self.port,
            "direction": self.direction,
            "from_ip":   self.from_ip,
            "to_ip":     self.to_ip,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            action    = d["action"],
            proto     = d.get("proto", "tcp"),
            port      = d.get("port", "any"),
            direction = d.get("direction", "in"),
            from_ip   = d.get("from_ip", "any"),
            to_ip     = d.get("to_ip", "any"),
            rule_id   = d.get("id"),
        )

    def matches(self, other: "Rule") -> bool:
        """Check if two rules are logically equivalent (ignoring id)."""
        return (self.action == other.action and
                self.proto == other.proto and
                self.port == other.port and
                self.direction == other.direction and
                self.from_ip == other.from_ip and
                self.to_ip == other.to_ip)

    def label(self) -> str:
        parts = [self.action, self.proto, f"port={self.port}", f"dir={self.direction}"]
        if self.from_ip != "any":
            parts.append(f"from={self.from_ip}")
        if self.to_ip != "any":
            parts.append(f"to={self.to_ip}")
        return " ".join(parts)

# ─────────────────────────────────────────
# State manager (rules.json)
# ─────────────────────────────────────────

class State:
    def __init__(self):
        self._data = {"enabled": False, "default_policy": "deny", "rules": []}
        self._load()

    def _load(self):
        if RULES_FILE.exists():
            try:
                with open(RULES_FILE) as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, KeyError):
                pass  # corrupt file — start fresh

    def _save(self):
        RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(RULES_FILE, "w") as f:
            json.dump(self._data, f, indent=2)

    @property
    def enabled(self) -> bool:
        return self._data.get("enabled", False)

    @enabled.setter
    def enabled(self, val: bool):
        self._data["enabled"] = val
        self._save()

    @property
    def default_policy(self) -> str:
        return self._data.get("default_policy", "deny")

    @default_policy.setter
    def default_policy(self, val: str):
        self._data["default_policy"] = val
        self._save()

    def get_rules(self) -> list[Rule]:
        return [Rule.from_dict(r) for r in self._data.get("rules", [])]

    def add_rule(self, rule: Rule) -> Rule:
        rules = self._data.get("rules", [])
        next_id = max((r.get("id", 0) for r in rules), default=0) + 1
        rule.id = next_id
        rules.append(rule.to_dict())
        self._data["rules"] = rules
        self._save()
        return rule

    def delete_rule(self, rule_id: int) -> bool:
        rules = self._data.get("rules", [])
        new_rules = [r for r in rules if r.get("id") != rule_id]
        if len(new_rules) == len(rules):
            return False
        self._data["rules"] = new_rules
        self._save()
        return True

    def find_matching(self, rule: Rule):
        for r in self.get_rules():
            if r.matches(rule):
                return r
        return None

    def clear_rules(self):
        self._data["rules"] = []
        self._save()

# ─────────────────────────────────────────
# Engine bridge (calls engine.sh)
# ─────────────────────────────────────────

class Engine:
    IPT_ACTION = {"allow": "ACCEPT", "deny": "DROP"}

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def _run(self, *args):
        cmd = ["bash", str(ENGINE_SH)] + [str(a) for a in args]
        self.log.debug(f"engine call: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.returncode != 0:
            err = result.stderr.strip()
            raise RuntimeError(f"engine.sh failed: {err}")

    def flush(self):
        self._run("flush")

    def set_policy(self, policy: str):
        # policy is "allow"/"deny" — convert to iptables terms
        ipt_policy = "ACCEPT" if policy == "allow" else "DROP"
        self._run("policy", ipt_policy)

    def apply_rule(self, rule: Rule):
        ipt_action = self.IPT_ACTION[rule.action]
        self._run("apply", ipt_action, rule.proto, rule.port,
                  rule.direction, rule.from_ip, rule.to_ip)

    def delete_rule(self, rule: Rule):
        ipt_action = self.IPT_ACTION[rule.action]
        self._run("delete", ipt_action, rule.proto, rule.port,
                  rule.direction, rule.from_ip, rule.to_ip)

    def status(self):
        self._run("status")

    def save(self):
        self._run("save")

    def restore(self):
        self._run("restore")

    def apply_all(self, state: State):
        """Flush and replay all saved rules (used on start)."""
        self.flush()
        self.set_policy(state.default_policy)
        for rule in state.get_rules():
            self.apply_rule(rule)
        self.save()

# ─────────────────────────────────────────
# Argument parser helpers
# ─────────────────────────────────────────

def parse_port_proto(spec: str) -> tuple[str, str]:
    """
    Parse '22', '80/tcp', '53/udp' → (port, proto).
    Default proto is tcp.
    """
    if "/" in spec:
        port, proto = spec.split("/", 1)
    else:
        port, proto = spec, "tcp"
    return port.strip(), proto.strip().lower()

# ─────────────────────────────────────────
# Commands
# ─────────────────────────────────────────

def cmd_start(state: State, engine: Engine, log: logging.Logger, cfg):
    if state.enabled:
        log.info("fwall is already running. Re-applying rules.")
    engine.apply_all(state)
    state.enabled = True
    log.info(f"fwall started. Default policy: {state.default_policy}. "
             f"Rules loaded: {len(state.get_rules())}")

def cmd_stop(state: State, engine: Engine, log: logging.Logger, cfg):
    engine.flush()
    state.enabled = False
    log.info("fwall stopped. All rules flushed.")

def cmd_enable(log: logging.Logger):
    result = subprocess.run(
        ["systemctl", "enable", "fwall"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info("fwall service enabled (will start on boot).")
    else:
        log.error(f"systemctl enable failed: {result.stderr.strip()}")

def cmd_disable(log: logging.Logger):
    result = subprocess.run(
        ["systemctl", "disable", "fwall"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info("fwall service disabled.")
    else:
        log.error(f"systemctl disable failed: {result.stderr.strip()}")

def cmd_status(state: State, engine: Engine, log: logging.Logger):
    status_str = "ACTIVE" if state.enabled else "INACTIVE"
    print(f"\n  fwall status: {status_str}")
    print(f"  Default policy: {state.default_policy.upper()}")
    rules = state.get_rules()
    print(f"  Rules ({len(rules)}):")
    if rules:
        for r in rules:
            print(f"    [{r.id:>3}]  {r.label()}")
    else:
        print("    (no rules defined)")
    print()
    engine.status()

def cmd_allow_deny(action: str, args, state: State, engine: Engine, log: logging.Logger):
    # Parse port/proto from positional or --port/--proto flags
    proto = "tcp"
    port = "any"
    from_ip = args.from_ip or "any"
    to_ip   = getattr(args, "to_ip", None) or "any"
    direction = getattr(args, "direction", "in") or "in"

    if args.port_proto:
        port, proto = parse_port_proto(args.port_proto)

    try:
        rule = Rule(action=action, proto=proto, port=port,
                    direction=direction, from_ip=from_ip, to_ip=to_ip)
    except ValueError as e:
        log.error(str(e))
        sys.exit(1)

    existing = state.find_matching(rule)
    if existing:
        log.warning(f"Rule already exists (id={existing.id}): {existing.label()}")
        return

    rule = state.add_rule(rule)
    if state.enabled:
        engine.apply_rule(rule)
        engine.save()
    log.info(f"Rule added (id={rule.id}): {rule.label()}")

def cmd_delete(args, state: State, engine: Engine, log: logging.Logger):
    # fwall delete <id>  OR  fwall delete allow|deny <port_proto>
    if args.rule_id is not None:
        rule_id = args.rule_id
        # Find the rule first (need it to remove from iptables)
        matched = next((r for r in state.get_rules() if r.id == rule_id), None)
        if not matched:
            log.error(f"No rule with id={rule_id}")
            sys.exit(1)
        if state.enabled:
            engine.delete_rule(matched)
        state.delete_rule(rule_id)
        log.info(f"Rule deleted (id={rule_id}): {matched.label()}")
    else:
        log.error("Specify a rule id: fwall delete <id>  (see fwall status)")
        sys.exit(1)

def cmd_default(args, state: State, engine: Engine, log: logging.Logger):
    policy = args.policy.lower()
    if policy not in ("allow", "deny"):
        log.error("Policy must be 'allow' or 'deny'")
        sys.exit(1)
    state.default_policy = policy
    if state.enabled:
        engine.set_policy(policy)
        engine.save()
    log.info(f"Default incoming policy set to: {policy.upper()}")

def cmd_reset(state: State, engine: Engine, log: logging.Logger):
    engine.flush()
    state.clear_rules()
    state.enabled = False
    log.info("fwall reset. All rules cleared, firewall stopped.")

def cmd_log(args, cfg: configparser.ConfigParser, log: logging.Logger):
    toggle = args.toggle.lower()
    if toggle not in ("on", "off"):
        log.error("Use: fwall log on|off")
        sys.exit(1)
    cfg.set("logging", "enabled", "true" if toggle == "on" else "false")
    CONF_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONF_FILE, "w") as f:
        cfg.write(f)
    log.info(f"Logging turned {toggle.upper()}.")

# ─────────────────────────────────────────
# CLI setup
# ─────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fwall",
        description="fwall — Simple Linux Firewall",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # start / stop / enable / disable / reset
    sub.add_parser("start",   help="Apply saved rules and activate firewall")
    sub.add_parser("stop",    help="Flush all rules (firewall off)")
    sub.add_parser("enable",  help="Enable fwall service on boot (systemctl)")
    sub.add_parser("disable", help="Disable fwall service on boot (systemctl)")
    sub.add_parser("status",  help="Show rules and iptables state")
    sub.add_parser("reset",   help="Clear all rules and stop firewall")

    # allow
    a = sub.add_parser("allow", help="Allow traffic. e.g. fwall allow 22/tcp")
    a.add_argument("port_proto",   nargs="?", help="Port or port/proto (e.g. 22, 80/tcp)")
    a.add_argument("--from",       dest="from_ip",   default=None, help="Source IP/subnet")
    a.add_argument("--to",         dest="to_ip",     default=None, help="Dest IP/subnet")
    a.add_argument("--direction",  default="in",     choices=["in","out"])

    # deny
    d = sub.add_parser("deny", help="Deny traffic. e.g. fwall deny 23")
    d.add_argument("port_proto",   nargs="?", help="Port or port/proto")
    d.add_argument("--from",       dest="from_ip",   default=None)
    d.add_argument("--to",         dest="to_ip",     default=None)
    d.add_argument("--direction",  default="in",     choices=["in","out"])

    # delete
    dl = sub.add_parser("delete", help="Delete a rule by id (see fwall status)")
    dl.add_argument("rule_id", type=int, nargs="?", help="Rule ID from status list")

    # default
    df = sub.add_parser("default", help="Set default incoming policy")
    df.add_argument("policy", choices=["allow", "deny"])

    # log
    lg = sub.add_parser("log", help="Toggle logging")
    lg.add_argument("toggle", choices=["on", "off"])

    return p

# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("[fwall] ERROR: fwall must be run as root (sudo fwall ...)", file=sys.stderr)
        sys.exit(1)

    cfg    = load_config()
    log    = setup_logger(cfg)
    state  = State()
    engine = Engine(log)

    parser = build_parser()
    args   = parser.parse_args()

    try:
        match args.command:
            case "start":   cmd_start(state, engine, log, cfg)
            case "stop":    cmd_stop(state, engine, log, cfg)
            case "enable":  cmd_enable(log)
            case "disable": cmd_disable(log)
            case "status":  cmd_status(state, engine, log)
            case "allow":   cmd_allow_deny("allow", args, state, engine, log)
            case "deny":    cmd_allow_deny("deny",  args, state, engine, log)
            case "delete":  cmd_delete(args, state, engine, log)
            case "default": cmd_default(args, state, engine, log)
            case "reset":   cmd_reset(state, engine, log)
            case "log":     cmd_log(args, cfg, log)
    except RuntimeError as e:
        log.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(0)

if __name__ == "__main__":
    main()
