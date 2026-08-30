#!/usr/bin/env python3
"""
Skjoldr Firewall CLI (Fedora/Linux port) — Avars/Mk2 daemon integration entry point.

Fedora port of SkjoldrCLI.ps1, ported 2026-08-30. Same verb/option contract and
JSON envelope as the Windows original, so Mk2's skjoldrFirewall.ts needs no
code changes — only addons.skjoldrFirewall.command in Mk2 config needs to
point at this file instead of the .ps1 (Mk2 spawns anything that isn't a
.ps1 directly, per its own isPs1() branch).

Usage: SkjoldrCLI.py <verb> [options]

Verbs:
    status                          Show firewall zone status
    export                          Export current state as a baseline snapshot
    apply --profile <name>          Apply a named profile (conservative | fortress | reset)
    apply --file <path>             Apply a ruleset file (.json)
    restore --snapshot <path>       Restore from an exported baseline snapshot
    lockdown                        Hard stop: radio kill (rfkill) + link-down + zero-exception
                                     firewall. Short of pulling power. See "lockdown vs fortress"
                                     below before ever invoking this for real.
    unlock                          Reverse a lockdown: unblock radios, bring links back up,
                                     restore firewall to the pre-Skjoldr/conservative baseline.

Lockdown vs fortress — these solve different problems:
  fortress is PORT-based and lets ANY process still reach dns/https/ntp. Most real
  C2/exfil rides exactly those ports, so fortress does NOT reliably stop a competent
  live compromise — it's containment/triage, not a hard stop. This was flagged
  directly (2026-08-30): "what is the point to a hardstop fire wall if it dosnt
  stop when needed?" — fair, and fortress alone isn't it.
  lockdown is a HARDWARE + zero-exception hard stop: rfkill block on wifi/bluetooth
  (kills the radio itself — no process, port, or protocol can transmit through a
  blocked radio) plus best-effort `ip link set down` on every interface plus a
  firewall policy with NO service exceptions at all (not even dns/https/ntp).
  Use lockdown when you mean "cut this box off from every network, right now,"
  short of physically pulling power — and unlike pulling power, Feneris keeps
  running and logging throughout (it makes no outbound calls of its own).
  CAVEAT: this also cuts off the very session invoking it (SSH, or any agent like
  Claude Code that needs its own network access) — `unlock` is a purely local
  operation (no network needed to run it), so recovery just requires a local
  terminal on this machine, not another device.

Options:
    --json                          Output JSON envelope { ok, data } or { ok, error_code, message }
    --dry-run                       Validate and preview without making changes
    --timeout <ms>                  Accepted for caller compatibility; not enforced here

Platform mapping (Windows -> Fedora/firewalld) — read this before assuming parity:
  - Windows' 3 fixed profiles (Domain/Private/Public) -> firewalld's active
    zone(s) on this box's interfaces (usually one: FedoraWorkstation on
    wlp4s0). Every profile op below acts on all currently ACTIVE zones.
  - "Block"/DefaultInboundAction -> zone target DROP (silent discard, same
    semantics Windows "Block" implies — not %%REJECT%%, which answers back).
  - conservative: target=DROP, strip the wide 1025-65535 tcp/udp open range
    (this is Fedora's own stock default, not something added later — see
    /usr/lib/firewalld/zones/FedoraWorkstation.xml), drop `ssh` from the
    allowed-services list (sshd is off; re-add explicitly via apply --file
    if it's ever turned back on), enable --set-log-denied=all.
  - fortress: everything conservative does, PLUS an attempt at "block all
    outbound except essentials." Windows does this per-executable via WFP
    (-Program <path>); nftables/firewalld have no equivalent — there is no
    "allow only these 6 binaries outbound" primitive on Linux without an
    external app-firewall daemon (e.g. OpenSnitch). This port approximates
    it with a firewalld POLICY object (ingress-zones=HOST, egress-zones=ANY,
    target=DROP) allowing only dns/https/ntp through. This is a real,
    native firewalld mechanism (not a hack), but it is coarser than the
    Windows version: any process can still reach 443, not just approved
    binaries. Documented here so nobody mistakes this for true parity.
  - apply --file rules with "program" set (Windows per-exe outbound rules)
    are NOT applied — reported back as skipped with an explicit reason,
    never silently dropped or reinterpreted.
  - reset: restores the most recent Skjoldr auto-backup for each active
    zone (taken automatically, once, the first time conservative/fortress
    ever mutates that zone — same "back up before the first destructive
    change" pattern as feneris/break-glass.sh), or falls back to the
    package-shipped stock definition in /usr/lib/firewalld/zones/ if no
    backup exists. Also removes the skjoldr-fortress policy object.

Ruleset file format (for apply --file) — identical schema to the Windows
version, "program" included for schema compatibility but unsupported here:
    {
      "profile": "conservative",       // optional: apply a named profile first
      "rules": [                        // optional: additional custom rules
        {
          "name": "SKJOLDR-Allow-SSH",
          "direction": "inbound",
          "action": "allow",
          "protocol": "TCP",
          "localPort": "22",
          "program": "",               // unsupported on Linux — rule skipped if set
          "enabled": true
        }
      ]
    }

Snapshot files are written to ./skjoldr-snapshots/ relative to this script.
Schema is tagged "v1-linux" (not "v1") so a Windows snapshot can never be
fed into --snapshot here or vice versa — cross-platform restore is refused
by construction, not by a runtime check that could be skipped.

Per the Bastion/Skjoldr separation law: this script only executes what it's
told (a named profile or an explicit ruleset file). It makes no independent
policy decisions — same as the Windows version.
"""

import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

try:
    import firewall.client as fwclient
except ImportError:
    fwclient = None

SNAPSHOT_SCHEMA = "v1-linux"
FORTRESS_POLICY_NAME = "skjoldr-fortress"
LOCKDOWN_POLICY_NAME = "skjoldr-lockdown"
BLOCK_TARGET = "DROP"  # silent discard — matches Windows "Block", not %%REJECT%%
ESSENTIAL_OUTBOUND_SERVICES = ["dns", "https", "ntp"]
LOCKDOWN_RADIOS = ["wifi", "bluetooth"]

SCRIPT_DIR = Path(__file__).resolve().parent
SNAPSHOT_DIR = SCRIPT_DIR / "skjoldr-snapshots"
LOCKDOWN_LOG = SNAPSHOT_DIR / "lockdown-events.log"

# ── Arg parsing (mirrors SkjoldrCLI.ps1 exactly) ─────────────────────────────

verb = ""
profile = ""
file_arg = ""
snapshot_arg = ""
use_json = False
dry_run = False

_args = sys.argv[1:]
_i = 0
while _i < len(_args):
    a = _args[_i]
    if a == "--json":
        use_json = True
    elif a == "--dry-run":
        dry_run = True
    elif a == "--profile":
        _i += 1
        if _i < len(_args):
            profile = _args[_i]
    elif a == "--file":
        _i += 1
        if _i < len(_args):
            file_arg = _args[_i]
    elif a == "--snapshot":
        _i += 1
        if _i < len(_args):
            snapshot_arg = _args[_i]
    elif a == "--timeout":
        _i += 1
    elif not a.startswith("-") and verb == "":
        verb = a.lower()
    _i += 1


# ── Output helpers (Write-Ok always emits JSON, matching the PS1 original) ──

def write_ok(data: dict) -> None:
    print(json.dumps({"ok": True, "data": data}))


def write_fail(error_code: str, message: str) -> None:
    if use_json:
        print(json.dumps({"ok": False, "error_code": error_code, "message": message}))
    else:
        print(f"{error_code}: {message}", file=sys.stderr)


class SkjoldrError(Exception):
    def __init__(self, error_code: str, message: str):
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ── Firewalld client ──────────────────────────────────────────────────────────

def _client():
    if fwclient is None:
        raise SkjoldrError("firewalld_unavailable",
                            "python3-firewall (firewall.client) is not installed")
    return fwclient.FirewallClient()


def _config(fc):
    return fc.config()


def get_active_zones(fc) -> list[str]:
    return list(fc.getActiveZones().keys())


def get_zone_data(fc, zone: str) -> dict:
    s = fc.getZoneSettings(zone)
    return {
        "name": zone,
        "target": s.getTarget(),
        "interfaces": list(s.getInterfaces()),
        "services": list(s.getServices()),
        "ports": [f"{p}/{proto}" for (p, proto) in s.getPorts()],
        "protocols": list(s.getProtocols()),
        "forward": bool(s.getForward()),
        "masquerade": bool(s.getMasquerade()),
        "rich_rules": list(s.getRichRules()),
    }


# ── SHA-256 helper ───────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ── Snapshot helpers ─────────────────────────────────────────────────────────

def export_snapshot(fc) -> Path:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    snapshot_path = SNAPSHOT_DIR / f"baseline-{ts}.json"

    zones = get_active_zones(fc)
    payload = {
        "skjoldr_snapshot": SNAPSHOT_SCHEMA,
        "platform": "fedora-firewalld",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "log_denied": fc.getLogDenied(),
        "zones": [get_zone_data(fc, z) for z in zones],
        "fortress_policy_present": FORTRESS_POLICY_NAME in _config(fc).getPolicyNames(),
    }
    snapshot_path.write_text(json.dumps(payload, indent=2))
    return snapshot_path


def set_log_denied(fc, value: str) -> None:
    """firewalld's setLogDenied() throws ALREADY_SET if called with the
    current value — not idempotent. Guard it so repeat applies (fortress
    calls conservative internally; a user may also just run the same
    profile twice) never crash on this."""
    if fc.getLogDenied() != value:
        fc.setLogDenied(value)


def import_snapshot(path: Path) -> dict:
    if not path.exists():
        raise SkjoldrError("file_not_found", f"Snapshot file not found: {path}")
    data = json.loads(path.read_text())
    if data.get("skjoldr_snapshot") != SNAPSHOT_SCHEMA:
        raise SkjoldrError(
            "unrecognised_schema",
            f"Unrecognised or cross-platform snapshot schema: {data.get('skjoldr_snapshot')!r} "
            f"(expected {SNAPSHOT_SCHEMA!r} — a Windows snapshot cannot be restored here)",
        )
    return data


def auto_backup_path(zone: str) -> Path:
    return SNAPSHOT_DIR / f"auto-backup-{zone}.json"


def ensure_auto_backup(fc, zone: str) -> None:
    """Back up a zone's settings the first time Skjoldr ever mutates it —
    same pattern as feneris/break-glass.sh: never overwrite an existing
    backup, so 'reset' always restores the true pre-Skjoldr state."""
    path = auto_backup_path(zone)
    if path.exists():
        return
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "skjoldr_snapshot": SNAPSHOT_SCHEMA,
        "platform": "fedora-firewalld",
        "backed_up_at": datetime.now(timezone.utc).isoformat(),
        "zone": get_zone_data(fc, zone),
        "log_denied": fc.getLogDenied(),
    }, indent=2))


def stock_zone_settings(zone: str) -> dict | None:
    """Read the package-shipped default for a zone directly from
    /usr/lib/firewalld/zones/ — world-readable, no root needed. Used as the
    reset fallback when no Skjoldr auto-backup exists."""
    stock_path = Path(f"/usr/lib/firewalld/zones/{zone}.xml")
    if not stock_path.exists():
        return None
    root = ET.parse(stock_path).getroot()
    return {
        "target": root.get("target", "default"),
        "services": [e.get("name") for e in root.findall("service")],
        "ports": [(e.get("port"), e.get("protocol")) for e in root.findall("port")],
        "protocols": [e.get("value") for e in root.findall("protocol")],
        "forward": root.find("forward") is not None,
        "masquerade": root.find("masquerade") is not None,
        "rich_rules": [],  # stock zone definitions never carry custom rich rules
    }


def apply_zone_settings(fc, zone: str, target: str, services: list[str],
                         ports: list, protocols: list[str],
                         forward: bool, masquerade: bool,
                         rich_rules: list[str] | None = None) -> None:
    """rich_rules defaults to None (leave whatever is currently set alone) —
    every caller that actually knows the desired rich-rule state (restore,
    reset) must pass it explicitly. This exists because a "block" apply
    --file rule is rich-rule-based, and forgetting to manage rich rules here
    would make such a block permanent and un-resettable — found via sandbox
    testing, not by inspection."""
    cfg = _config(fc)
    czone = cfg.getZoneByName(zone)
    settings = czone.getSettings()
    settings.setTarget(target)
    settings.setServices(services)
    settings.setPorts([(p, proto) for (p, proto) in ports])
    settings.setProtocols(protocols)
    settings.setForward(forward)
    settings.setMasquerade(masquerade)
    if rich_rules is not None:
        settings.setRichRules(rich_rules)
    czone.update(settings)
    fc.reload()


# ── Firewall operations ──────────────────────────────────────────────────────

def apply_conservative_profile(fc) -> None:
    for zone in get_active_zones(fc):
        ensure_auto_backup(fc, zone)
        data = get_zone_data(fc, zone)
        services = [s for s in data["services"] if s != "ssh"]
        # Strip Fedora's stock wide-open ephemeral-port range; keep anything
        # else (e.g. custom SKJOLDR ports from a prior apply --file) intact.
        ports = [tuple(p.split("/")) for p in data["ports"]
                 if p not in ("1025-65535/tcp", "1025-65535/udp")]
        apply_zone_settings(fc, zone, BLOCK_TARGET, services, ports,
                             data["protocols"], data["forward"], data["masquerade"])
    set_log_denied(fc, "all")


def apply_fortress_profile(fc) -> None:
    apply_conservative_profile(fc)

    cfg = _config(fc)
    settings = fwclient.FirewallClientPolicySettings()
    settings.setIngressZones(["HOST"])
    settings.setEgressZones(["ANY"])
    settings.setTarget(BLOCK_TARGET)
    for svc in ESSENTIAL_OUTBOUND_SERVICES:
        settings.addService(svc)

    if FORTRESS_POLICY_NAME in cfg.getPolicyNames():
        cfg.getPolicyByName(FORTRESS_POLICY_NAME).update(settings)
    else:
        cfg.addPolicy(FORTRESS_POLICY_NAME, settings)
    fc.reload()


def apply_reset_profile(fc) -> dict:
    restored = {}
    for zone in get_active_zones(fc):
        backup = auto_backup_path(zone)
        if backup.exists():
            data = json.loads(backup.read_text())["zone"]
            apply_zone_settings(
                fc, zone, data["target"], data["services"],
                [tuple(p.split("/")) for p in data["ports"]],
                data["protocols"], data["forward"], data["masquerade"],
                rich_rules=data.get("rich_rules", []),
            )
            restored[zone] = "skjoldr_auto_backup"
        else:
            stock = stock_zone_settings(zone)
            if stock is None:
                restored[zone] = "no_backup_no_stock_definition_found"
                continue
            apply_zone_settings(
                fc, zone, stock["target"], stock["services"], stock["ports"],
                stock["protocols"], stock["forward"], stock["masquerade"],
                rich_rules=stock["rich_rules"],
            )
            restored[zone] = "package_stock_default"

    cfg = _config(fc)
    if FORTRESS_POLICY_NAME in cfg.getPolicyNames():
        cfg.getPolicyByName(FORTRESS_POLICY_NAME).remove()

    set_log_denied(fc, "off")
    fc.reload()
    return restored


def invoke_named_profile(fc, name: str):
    if name == "conservative":
        apply_conservative_profile(fc)
        return None
    if name == "fortress":
        apply_fortress_profile(fc)
        return None
    if name == "reset":
        return apply_reset_profile(fc)
    raise SkjoldrError("invalid_profile",
                        f"Unknown profile: '{name}'. Valid: conservative | fortress | reset")


# ── Verb: status ─────────────────────────────────────────────────────────────

def invoke_status(fc) -> None:
    zones = [get_zone_data(fc, z) for z in get_active_zones(fc)]
    write_ok({
        "zones": zones,
        "log_denied": fc.getLogDenied(),
        "fortress_policy_present": FORTRESS_POLICY_NAME in _config(fc).getPolicyNames(),
    })


# ── Verb: export ─────────────────────────────────────────────────────────────

def invoke_export(fc) -> None:
    if dry_run:
        zones = get_active_zones(fc)
        write_ok({
            "dry_run": True,
            "planned_zone_count": len(zones),
            "zones": zones,
            "snapshot_dir": str(SNAPSHOT_DIR),
        })
        return

    snapshot_path = export_snapshot(fc)
    write_ok({
        "snapshot_path": str(snapshot_path),
        "hash": sha256_file(snapshot_path),
        "exported_at": datetime.now(timezone.utc).isoformat(),
    })


# ── Verb: apply ──────────────────────────────────────────────────────────────

def invoke_apply(fc) -> None:
    if profile != "":
        invoke_apply_profile(fc)
    elif file_arg != "":
        invoke_apply_file(fc)
    else:
        raise SkjoldrError("missing_argument", "apply requires --profile <name> or --file <path>")


def invoke_apply_profile(fc) -> None:
    name = profile.lower().strip()
    valid = ("conservative", "fortress", "reset")
    if name not in valid:
        raise SkjoldrError("invalid_profile", f"Unknown profile: '{profile}'. Valid: {' | '.join(valid)}")

    if dry_run:
        planned = {
            "conservative": "Set active zone(s) target=DROP, strip the 1025-65535 open range, "
                             "drop ssh from allowed services, enable log-denied=all",
            "fortress": "Everything conservative does, plus a HOST-egress policy object "
                        "blocking all outbound except dns/https/ntp (approximation — see script docstring)",
            "reset": "Restore each active zone from its Skjoldr auto-backup (or package "
                     "stock default if none exists); remove the fortress policy object",
        }[name]
        write_ok({"dry_run": True, "profile": name, "planned_action": planned})
        return

    result = invoke_named_profile(fc, name)
    zones = [get_zone_data(fc, z) for z in get_active_zones(fc)]
    payload = {"profile": name, "applied": True, "post_status": {"zones": zones}}
    if result is not None:
        payload["restored_from"] = result
    write_ok(payload)


def invoke_apply_file(fc) -> None:
    path = Path(file_arg)
    if not path.exists():
        raise SkjoldrError("file_not_found", f"Ruleset file not found: {file_arg}")

    ruleset = json.loads(path.read_text())

    if dry_run:
        planned = []
        if ruleset.get("profile"):
            planned.append(f"Apply profile: {ruleset['profile']}")
        rules = ruleset.get("rules", [])
        if rules:
            planned.append(f"Create/evaluate {len(rules)} custom rule(s)")
        write_ok({
            "dry_run": True,
            "file": file_arg,
            "planned_actions": planned,
            "rule_count": len(rules),
        })
        return

    applied = []
    skipped = []

    if ruleset.get("profile"):
        invoke_named_profile(fc, ruleset["profile"].lower().strip())
        applied.append(f"profile:{ruleset['profile']}")

    for zone in get_active_zones(fc):
        ensure_auto_backup(fc, zone)
        cfg = _config(fc)
        czone = cfg.getZoneByName(zone)
        settings = czone.getSettings()
        dirty = False

        for rule in ruleset.get("rules", []):
            name = rule.get("name", "")
            direction = rule.get("direction", "inbound")
            action = rule.get("action", "allow")
            enabled = rule.get("enabled", True)
            protocol = (rule.get("protocol") or "").lower()
            local_port = rule.get("localPort") or ""
            program = rule.get("program") or ""

            if not enabled:
                skipped.append({"rule": name, "reason": "disabled"})
                continue
            if program:
                skipped.append({
                    "rule": name,
                    "reason": "per-executable outbound filtering is unsupported on Linux "
                              "(no nftables/firewalld equivalent to Windows -Program); "
                              "use apply --profile fortress for a port-based approximation",
                })
                continue
            if not local_port or not protocol:
                skipped.append({"rule": name, "reason": "protocol and localPort are required on this port"})
                continue

            if direction == "inbound":
                if action == "allow":
                    settings.addPort(local_port, protocol)
                else:
                    settings.addRichRule(
                        f'rule family="ipv4" port port="{local_port}" protocol="{protocol}" drop'
                    )
                dirty = True
                applied.append(f"rule:{name}")
            else:
                skipped.append({
                    "rule": name,
                    "reason": "outbound port-based rules require apply --profile fortress "
                              "(HOST-egress policy) — not supported via apply --file yet",
                })

        if dirty:
            czone.update(settings)

    fc.reload()
    zones = [get_zone_data(fc, z) for z in get_active_zones(fc)]
    write_ok({"file": file_arg, "applied": applied, "skipped": skipped,
              "post_status": {"zones": zones}})


# ── Verb: restore ────────────────────────────────────────────────────────────

def invoke_restore(fc) -> None:
    if snapshot_arg == "":
        raise SkjoldrError("missing_argument", "restore requires --snapshot <path>")

    data = import_snapshot(Path(snapshot_arg))

    if dry_run:
        write_ok({
            "dry_run": True,
            "snapshot": snapshot_arg,
            "exported_at": data.get("exported_at"),
            "zone_count": len(data.get("zones", [])),
        })
        return

    for zone_data in data.get("zones", []):
        zone = zone_data["name"]
        ports = [tuple(p.split("/")) for p in zone_data["ports"]]
        apply_zone_settings(fc, zone, zone_data["target"], zone_data["services"],
                             ports, zone_data["protocols"], zone_data["forward"],
                             zone_data["masquerade"],
                             rich_rules=zone_data.get("rich_rules", []))

    if "log_denied" in data:
        set_log_denied(fc, data["log_denied"])

    cfg = _config(fc)
    fortress_present = data.get("fortress_policy_present", False)
    if not fortress_present and FORTRESS_POLICY_NAME in cfg.getPolicyNames():
        cfg.getPolicyByName(FORTRESS_POLICY_NAME).remove()
        fc.reload()

    zones = [get_zone_data(fc, z) for z in get_active_zones(fc)]
    write_ok({
        "snapshot": snapshot_arg,
        "restored": True,
        "exported_at": data.get("exported_at"),
        "post_status": {"zones": zones},
    })


# ── Lockdown helpers (rfkill/ip are separate from firewalld's D-Bus API) ────────

def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout running: {' '.join(cmd)}"


def list_links() -> list[dict]:
    """All non-loopback interfaces via `ip -j link show` — works without root."""
    rc, out, _err = _run(["ip", "-j", "link", "show"])
    if rc != 0 or not out:
        return []
    return [link for link in json.loads(out) if link.get("ifname") != "lo"]


def append_lockdown_log(event: dict) -> None:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    with LOCKDOWN_LOG.open("a") as f:
        f.write(json.dumps(event) + "\n")


# ── Verb: lockdown ───────────────────────────────────────────────────────────

def invoke_lockdown(fc) -> None:
    if dry_run:
        up_links = [link.get("ifname") for link in list_links() if "UP" in (link.get("flags") or [])]
        write_ok({
            "dry_run": True,
            "planned_action": (
                "rfkill block on " + ", ".join(LOCKDOWN_RADIOS) + " (hardware radio kill); "
                "best-effort `ip link set down` on every UP non-loopback interface; "
                "firewall policy with ZERO outbound exceptions (no dns/https/ntp, unlike fortress)"
            ),
            "would_affect_interfaces": up_links,
        })
        return

    pre_rfkill = _run(["rfkill", "list"])[1]

    rfkill_results = {}
    for radio in LOCKDOWN_RADIOS:
        rc, out, err = _run(["rfkill", "block", radio])
        rfkill_results[radio] = "blocked" if rc == 0 else f"failed: {err or out}"

    link_results = {}
    for link in list_links():
        ifname = link.get("ifname")
        if "UP" not in (link.get("flags") or []):
            continue
        rc, out, err = _run(["ip", "link", "set", ifname, "down"])
        link_results[ifname] = "down" if rc == 0 else f"failed (likely needs root): {err or out}"

    for zone in get_active_zones(fc):
        ensure_auto_backup(fc, zone)
        data = get_zone_data(fc, zone)
        apply_zone_settings(fc, zone, BLOCK_TARGET, [], [], [],
                             data["forward"], False, rich_rules=[])
    set_log_denied(fc, "all")

    cfg = _config(fc)
    settings = fwclient.FirewallClientPolicySettings()
    settings.setIngressZones(["HOST"])
    settings.setEgressZones(["ANY"])
    settings.setTarget(BLOCK_TARGET)
    # No addService() calls, deliberately — zero exceptions, unlike fortress's
    # dns/https/ntp allowance. This is the whole point of this verb.
    if LOCKDOWN_POLICY_NAME in cfg.getPolicyNames():
        cfg.getPolicyByName(LOCKDOWN_POLICY_NAME).update(settings)
    else:
        cfg.addPolicy(LOCKDOWN_POLICY_NAME, settings)
    fc.reload()

    append_lockdown_log({
        "event": "lockdown",
        "at": datetime.now(timezone.utc).isoformat(),
        "rfkill_before": pre_rfkill,
        "rfkill_actions": rfkill_results,
        "link_actions": link_results,
    })

    write_ok({
        "locked_down": True,
        "rfkill": rfkill_results,
        "links": link_results,
        "note": "Radios are the primary hard stop (no process/port/protocol transmits through "
                "a blocked radio); the zero-exception firewall policy is defense-in-depth in "
                "case a radio gets unblocked by something else. Feneris keeps running — it "
                "makes no outbound calls of its own. Run `unlock` (local-only, no network "
                "needed) to reverse.",
    })


# ── Verb: unlock ─────────────────────────────────────────────────────────────

def invoke_unlock(fc) -> None:
    if dry_run:
        write_ok({
            "dry_run": True,
            "planned_action": (
                "rfkill unblock on " + ", ".join(LOCKDOWN_RADIOS) + "; `ip link set up` on every "
                "interface; remove the lockdown policy object; restore firewall from Skjoldr's "
                "auto-backup (same as apply --profile reset)"
            ),
        })
        return

    rfkill_results = {}
    for radio in LOCKDOWN_RADIOS:
        rc, out, err = _run(["rfkill", "unblock", radio])
        rfkill_results[radio] = "unblocked" if rc == 0 else f"failed: {err or out}"

    link_results = {}
    for link in list_links():
        ifname = link.get("ifname")
        rc, out, err = _run(["ip", "link", "set", ifname, "up"])
        link_results[ifname] = "up" if rc == 0 else f"failed (likely needs root): {err or out}"

    cfg = _config(fc)
    if LOCKDOWN_POLICY_NAME in cfg.getPolicyNames():
        cfg.getPolicyByName(LOCKDOWN_POLICY_NAME).remove()

    restored = apply_reset_profile(fc)

    append_lockdown_log({
        "event": "unlock",
        "at": datetime.now(timezone.utc).isoformat(),
        "rfkill_actions": rfkill_results,
        "link_actions": link_results,
    })

    write_ok({
        "unlocked": True,
        "rfkill": rfkill_results,
        "links": link_results,
        "restored_from": restored,
    })


# ── Dispatch ─────────────────────────────────────────────────────────────────

def main() -> int:
    try:
        fc = _client()
        if verb == "status":
            invoke_status(fc)
        elif verb == "export":
            invoke_export(fc)
        elif verb == "apply":
            invoke_apply(fc)
        elif verb == "restore":
            invoke_restore(fc)
        elif verb == "lockdown":
            invoke_lockdown(fc)
        elif verb == "unlock":
            invoke_unlock(fc)
        else:
            write_fail("unknown_verb",
                       f"Unknown verb: '{verb}'. Expected: status | export | apply | restore | lockdown | unlock")
            return 1
        return 0
    except SkjoldrError as e:
        write_fail(e.error_code, e.message)
        return 1
    except Exception as e:  # noqa: BLE001 — mirrors the PS1's top-level catch-all
        write_fail("internal_error", str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
