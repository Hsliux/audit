#!/usr/bin/env python3
"""Stage/rollback opt-in files. No service restarts or audit-rule changes."""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
MANIFEST = "var/lib/infra-audit-poc/manifest.json"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def paths():
    return {
        "etc/profile.d/99-infra-audit.sh": (PROJECT / "scripts/bash_audit.sh").read_bytes(),
        "etc/rsyslog.d/70-infra-audit.conf": None,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=("deploy", "rollback"))
    p.add_argument("--root", required=True, type=Path, help="target filesystem root")
    p.add_argument("--apply", action="store_true", help="otherwise print a dry run")
    p.add_argument("--allow-live", action="store_true", help="required for --root /")
    p.add_argument("--remote", help="Rsyslog destination host for deploy")
    p.add_argument("--port", type=int, default=6514)
    p.add_argument("--transport", choices=("tls", "tcp-lab"), default="tls")
    p.add_argument("--host-input", choices=("none", "debian", "rhel", "custom"), default="none",
                   help="optionally forward raw auditd and SSH/sudo auth logs")
    p.add_argument("--auth-log", help="absolute auth log path when --host-input custom")
    args = p.parse_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        p.error("--root must be a directory")
    if root == Path("/") and not args.allow_live:
        p.error("live root requires --allow-live")
    if args.operation == "deploy":
        if not args.remote or not re.fullmatch(r"[A-Za-z0-9_.:-]+", args.remote):
            p.error("--remote must be a DNS name or IP without shell/config metacharacters")
        if not 1 <= args.port <= 65535:
            p.error("--port must be 1..65535")
        payloads = paths()
        template_name = "rsyslog-forward-tls.conf.in" if args.transport == "tls" else "rsyslog-forward.conf.in"
        template = (PROJECT / "config" / template_name).read_text()
        payloads["etc/rsyslog.d/70-infra-audit.conf"] = template.replace("__REMOTE_HOST__", args.remote).replace("__REMOTE_PORT__", str(args.port)).encode()
        if args.host_input != "none":
            auth_path = {"debian": "/var/log/auth.log", "rhel": "/var/log/secure"}.get(args.host_input, args.auth_log)
            if not auth_path or not re.fullmatch(r"/[A-Za-z0-9._/-]+", auth_path) or ".." in Path(auth_path).parts:
                p.error("--auth-log must be an absolute path without config metacharacters")
            ruleset = "infra_audit_forward_tls" if args.transport == "tls" else "infra_audit_forward"
            host_template = (PROJECT / "config/rsyslog-host-inputs.conf.in").read_text()
            payloads["etc/rsyslog.d/71-infra-audit-host-inputs.conf"] = host_template.replace("__AUTH_LOG__", auth_path).replace("__RULESET__", ruleset).encode()
        manifest_path = root / MANIFEST
        if manifest_path.exists():
            p.error(f"deployment manifest already exists: {manifest_path}")
        record = {}
        for rel, data in payloads.items():
            target = root / rel
            if target.is_symlink():
                p.error(f"refusing symlink target: {target}")
            prior = target.read_bytes() if target.exists() else None
            record[rel] = {"new_sha256": digest(data), "prior_b64": base64.b64encode(prior).decode() if prior is not None else None,
                           "prior_mode": target.stat().st_mode & 0o777 if prior is not None else None}
            print(f"install {target} (backup={'yes' if prior is not None else 'no'})")
        if args.apply:
            for rel, data in payloads.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o644)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(record, indent=2))
            manifest_path.chmod(0o600)
            print("installed; validate rsyslog and restart it only after review")
    else:
        manifest_path = root / MANIFEST
        if not manifest_path.is_file():
            p.error(f"missing deployment manifest: {manifest_path}")
        record = json.loads(manifest_path.read_text())
        for rel, state in record.items():
            target = root / rel
            if target.is_symlink() or not target.is_file() or digest(target.read_bytes()) != state["new_sha256"]:
                p.error(f"file changed since deployment; refusing rollback: {target}")
            print(f"restore {target}" if state["prior_b64"] is not None else f"remove {target}")
        if args.apply:
            for rel, state in record.items():
                target = root / rel
                if state["prior_b64"] is None:
                    target.unlink()
                else:
                    target.write_bytes(base64.b64decode(state["prior_b64"]))
                    target.chmod(state["prior_mode"])
            manifest_path.unlink()
            print("files rolled back; validate rsyslog and restart it only after review")


if __name__ == "__main__":
    main()
