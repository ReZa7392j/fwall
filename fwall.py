#!/usr/bin/env python3
"""fwall — Simple Linux Firewall. Must be run as root."""
import argparse, configparser, json, logging, os, subprocess, sys
from pathlib import Path

CONF_FILE  = Path("/etc/fwall/fwall.conf")
RULES_FILE = Path("/etc/fwall/rules.json")
LOG_FILE   = Path("/var/log/fwall.log")
ENGINE_SH  = Path("/usr/local/lib/fwall/engine.sh")

ACTIONS = {"allow", "deny"}
PROTOS  = {"tcp", "udp", "any"}
DIRS    = {"in", "out"}
IPT_ACTION = {"allow": "ACCEPT", "deny": "DROP"}


def load_config():
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "policy":  {"default_incoming": "deny", "default_outgoing": "allow"},
        "logging": {"enabled": "true", "level": "info", "path": str(LOG_FILE)},
        "engine":  {"backend": "iptables"},
    })
    if CONF_FILE.exists():
        cfg.read(CONF_FILE)
    return cfg


def setup_logger(cfg):
    log = logging.getLogger("fwall")
    if not cfg.getboolean("logging", "enabled", fallback=True):
        log.addHandler(logging.NullHandler())
        return log
    level = getattr(logging, cfg.get("logging", "level", fallback="info").upper(), logging.INFO)
    log.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[fwall] %(levelname)s: %(message)s"))
    log.addHandler(ch)
    try:
        path = cfg.get("logging", "path", fallback=str(LOG_FILE))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(path)
        fh.setFormatter(logging.Formatter("%(asctime)s [fwall] %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
        log.addHandler(fh)
    except PermissionError:
        log.warning(f"Cannot write log file {path} — file logging disabled.")
    return log


def parse_port_proto(spec):
    port, _, proto = spec.partition("/")
    return port.strip(), (proto.strip().lower() or "tcp")


class Rule:
    __slots__ = ("id", "action", "proto", "port", "direction", "from_ip", "to_ip")

    def __init__(self, action, proto="tcp", port="any", direction="in", from_ip="any", to_ip="any", rule_id=None):
        self.id, self.action, self.proto = rule_id, action.lower(), proto.lower()
        self.port, self.direction = str(port), direction.lower()
        self.from_ip, self.to_ip = from_ip or "any", to_ip or "any"
        if self.action not in ACTIONS:
            raise ValueError(f"Invalid action '{self.action}'. Use: allow, deny")
        if self.proto not in PROTOS:
            raise ValueError(f"Invalid protocol '{self.proto}'. Use: tcp, udp, any")
        if self.direction not in DIRS:
            raise ValueError(f"Invalid direction '{self.direction}'. Use: in, out")
        if self.port != "any" and not (self.port.isdigit() and 1 <= int(self.port) <= 65535):
            raise ValueError(f"Invalid port '{self.port}'. Use 1-65535 or 'any'")

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}

    @classmethod
    def from_dict(cls, d):
        return cls(d["action"], d.get("proto", "tcp"), d.get("port", "any"),
                   d.get("direction", "in"), d.get("from_ip", "any"), d.get("to_ip", "any"), d.get("id"))

    def matches(self, other):
        return all(getattr(self, k) == getattr(other, k) for k in self.__slots__ if k != "id")

    def label(self):
        parts = [self.action, self.proto, f"port={self.port}", f"dir={self.direction}"]
        if self.from_ip != "any": parts.append(f"from={self.from_ip}")
        if self.to_ip != "any":   parts.append(f"to={self.to_ip}")
        return " ".join(parts)


class State:
    def __init__(self):
        self.d = {"enabled": False, "default_policy": "deny", "rules": []}
        if RULES_FILE.exists():
            try:
                self.d = json.loads(RULES_FILE.read_text())
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        RULES_FILE.write_text(json.dumps(self.d, indent=2))

    @property
    def enabled(self): return self.d.get("enabled", False)
    @enabled.setter
    def enabled(self, v): self.d["enabled"] = v; self._save()

    @property
    def default_policy(self): return self.d.get("default_policy", "deny")
    @default_policy.setter
    def default_policy(self, v): self.d["default_policy"] = v; self._save()

    def get_rules(self): return [Rule.from_dict(r) for r in self.d.get("rules", [])]

    def add_rule(self, rule):
        rules = self.d.get("rules", [])
        rule.id = max((r.get("id", 0) for r in rules), default=0) + 1
        rules.append(rule.to_dict())
        self.d["rules"] = rules
        self._save()
        return rule

    def delete_rule(self, rule_id):
        rules = self.d.get("rules", [])
        new = [r for r in rules if r.get("id") != rule_id]
        if len(new) == len(rules):
            return False
        self.d["rules"] = new
        self._save()
        return True

    def find_matching(self, rule):
        return next((r for r in self.get_rules() if r.matches(rule)), None)

    def clear_rules(self): self.d["rules"] = []; self._save()


class Engine:
    def __init__(self, log): self.log = log

    def _run(self, *args):
        cmd = ["bash", str(ENGINE_SH), *map(str, args)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout: print(result.stdout, end="")
        if result.returncode != 0:
            raise RuntimeError(f"engine.sh failed: {result.stderr.strip()}")

    def flush(self): self._run("flush")
    def set_policy(self, policy): self._run("policy", "ACCEPT" if policy == "allow" else "DROP")
    def apply_rule(self, r): self._run("apply", IPT_ACTION[r.action], r.proto, r.port, r.direction, r.from_ip, r.to_ip)
    def delete_rule(self, r): self._run("delete", IPT_ACTION[r.action], r.proto, r.port, r.direction, r.from_ip, r.to_ip)
    def status(self): self._run("status")
    def save(self): self._run("save")
    def restore(self): self._run("restore")

    def apply_all(self, state):
        self.flush()
        self.set_policy(state.default_policy)
        for r in state.get_rules():
            self.apply_rule(r)
        self.save()


# ── Commands ──────────────────────────────────────────────

def cmd_start(state, engine, log):
    if state.enabled:
        log.info("fwall is already running. Re-applying rules.")
    engine.apply_all(state)
    state.enabled = True
    log.info(f"fwall started. Default policy: {state.default_policy}. Rules loaded: {len(state.get_rules())}")


def cmd_stop(state, engine, log):
    engine.flush()
    state.enabled = False
    log.info("fwall stopped. All rules flushed.")


def cmd_systemctl(action, log):
    r = subprocess.run(["systemctl", action, "fwall"], capture_output=True, text=True)
    if r.returncode == 0:
        log.info(f"fwall service {action}d.")
    else:
        log.error(f"systemctl {action} failed: {r.stderr.strip()}")


def cmd_status(state, engine, log):
    print(f"\n  fwall status: {'ACTIVE' if state.enabled else 'INACTIVE'}")
    print(f"  Default policy: {state.default_policy.upper()}")
    rules = state.get_rules()
    print(f"  Rules ({len(rules)}):")
    for r in rules:
        print(f"    [{r.id:>3}]  {r.label()}")
    if not rules:
        print("    (no rules defined)")
    print()
    engine.status()


def cmd_allow_deny(action, args, state, engine, log):
    proto, port = "tcp", "any"
    if args.port_proto:
        port, proto = parse_port_proto(args.port_proto)
    try:
        rule = Rule(action, proto, port, args.direction, args.from_ip, args.to_ip)
    except ValueError as e:
        log.error(str(e)); sys.exit(1)

    existing = state.find_matching(rule)
    if existing:
        log.warning(f"Rule already exists (id={existing.id}): {existing.label()}")
        return
    rule = state.add_rule(rule)
    if state.enabled:
        engine.apply_rule(rule)
        engine.save()
    log.info(f"Rule added (id={rule.id}): {rule.label()}")


def cmd_delete(args, state, engine, log):
    if args.rule_id is None:
        log.error("Specify a rule id: fwall delete <id>  (see fwall status)")
        sys.exit(1)
    matched = next((r for r in state.get_rules() if r.id == args.rule_id), None)
    if not matched:
        log.error(f"No rule with id={args.rule_id}"); sys.exit(1)
    if state.enabled:
        engine.delete_rule(matched)
    state.delete_rule(args.rule_id)
    log.info(f"Rule deleted (id={args.rule_id}): {matched.label()}")


def cmd_default(args, state, engine, log):
    state.default_policy = args.policy
    if state.enabled:
        engine.set_policy(args.policy)
        engine.save()
    log.info(f"Default incoming policy set to: {args.policy.upper()}")


def cmd_reset(state, engine, log):
    engine.flush()
    state.clear_rules()
    state.enabled = False
    log.info("fwall reset. All rules cleared, firewall stopped.")


def cmd_log(args, cfg, log):
    cfg.set("logging", "enabled", "true" if args.toggle == "on" else "false")
    CONF_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONF_FILE, "w") as f:
        cfg.write(f)
    log.info(f"Logging turned {args.toggle.upper()}.")


# ── CLI ───────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(prog="fwall", description="fwall — Simple Linux Firewall")
    sub = p.add_subparsers(dest="command", required=True)

    for name, help_ in [("start", "Apply saved rules and activate firewall"),
                         ("stop", "Flush all rules (firewall off)"),
                         ("enable", "Enable fwall on boot"),
                         ("disable", "Disable fwall on boot"),
                         ("status", "Show rules and iptables state"),
                         ("reset", "Clear all rules and stop firewall")]:
        sub.add_parser(name, help=help_)

    for name in ("allow", "deny"):
        sp = sub.add_parser(name, help=f"{name.capitalize()} traffic, e.g. fwall {name} 22/tcp")
        sp.add_argument("port_proto", nargs="?", help="Port or port/proto (e.g. 22, 80/tcp)")
        sp.add_argument("--from", dest="from_ip", default="any", help="Source IP/subnet")
        sp.add_argument("--to", dest="to_ip", default="any", help="Dest IP/subnet")
        sp.add_argument("--direction", default="in", choices=["in", "out"])

    dl = sub.add_parser("delete", help="Delete a rule by id (see fwall status)")
    dl.add_argument("rule_id", type=int, nargs="?")

    df = sub.add_parser("default", help="Set default incoming policy")
    df.add_argument("policy", choices=["allow", "deny"])

    lg = sub.add_parser("log", help="Toggle logging")
    lg.add_argument("toggle", choices=["on", "off"])

    return p


def main():
    if os.geteuid() != 0:
        sys.exit("[fwall] ERROR: must be run as root (sudo fwall ...)")

    cfg, args = load_config(), build_parser().parse_args()
    log, state, engine = setup_logger(cfg), State(), Engine(None)
    engine.log = log

    try:
        match args.command:
            case "start":   cmd_start(state, engine, log)
            case "stop":    cmd_stop(state, engine, log)
            case "enable":  cmd_systemctl("enable", log)
            case "disable": cmd_systemctl("disable", log)
            case "status":  cmd_status(state, engine, log)
            case "allow":   cmd_allow_deny("allow", args, state, engine, log)
            case "deny":    cmd_allow_deny("deny", args, state, engine, log)
            case "delete":  cmd_delete(args, state, engine, log)
            case "default": cmd_default(args, state, engine, log)
            case "reset":   cmd_reset(state, engine, log)
            case "log":     cmd_log(args, cfg, log)
    except RuntimeError as e:
        log.error(str(e)); sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
