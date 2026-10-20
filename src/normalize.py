#!/usr/bin/env python3
"""Small, dependency-free event mapper. Input is JSON Lines; output is JSON Lines."""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone


def get(obj, *path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def timestamp(value):
    if isinstance(value, (int, float)):
        # Docker TimeNano uses nanoseconds; regular Unix time uses seconds.
        if value > 10**15:
            value /= 10**9
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str) and value:
        return value
    return None


def base(source, raw, host):
    return {
        "schema_version": "1.0",
        "event_id": "",
        "time": timestamp(raw.get("time") or raw.get("timestamp")),
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": source,
        "actor": {"user": None, "uid": None},
        "host": host,
        "tty": None,
        "container_id": None,
        "pod": None,
        "namespace": None,
        "vm_id": None,
        "action": None,
        "target": None,
        "result": None,
        "correlation_id": None,
        "details": {},
    }


def normalize(source, raw, host=None):
    if not isinstance(raw, dict):
        raise ValueError("event must be a JSON object")
    e = base(source, raw, host or raw.get("host") or "unknown")
    if source == "shell":
        e["time"] = timestamp(raw.get("time"))
        e["actor"] = {"user": raw.get("user"), "uid": raw.get("uid")}
        e["host"] = raw.get("host") or e["host"]
        e["tty"] = raw.get("tty")
        e["container_id"] = raw.get("container_id")
        e["pod"] = raw.get("pod")
        e["namespace"] = raw.get("namespace")
        e["action"] = "shell.command.preexec"
        e["correlation_id"] = raw.get("session_id")
        e["details"] = {"command_b64": raw.get("command_b64"), "sequence": raw.get("sequence"), "capture": "bash.DEBUG.preexec"}
        # Do not decode and duplicate command text: base64 is transport, not redaction.
    elif source == "docker":
        actor = raw.get("Actor") or {}
        attrs = actor.get("Attributes") or {}
        e["time"] = timestamp(raw.get("timeNano") or raw.get("time"))
        e["action"] = f"docker.{raw.get('Type', 'unknown')}.{raw.get('Action', 'unknown')}"
        e["container_id"] = actor.get("ID") if raw.get("Type") == "container" else None
        e["target"] = actor.get("ID")
        e["pod"] = attrs.get("io.kubernetes.pod.name")
        e["namespace"] = attrs.get("io.kubernetes.pod.namespace")
        e["details"] = {"attributes": attrs, "scope": raw.get("scope")}
    elif source == "k8s_audit":
        obj = raw.get("objectRef") or {}
        user = raw.get("user") or {}
        e["time"] = timestamp(raw.get("requestReceivedTimestamp") or raw.get("stageTimestamp"))
        e["actor"] = {"user": user.get("username"), "uid": user.get("uid")}
        e["action"] = f"k8s.{raw.get('verb', 'unknown')}"
        e["target"] = "/".join(str(x) for x in (obj.get("resource"), obj.get("name")) if x)
        e["pod"] = obj.get("name") if obj.get("resource") == "pods" else None
        e["namespace"] = obj.get("namespace")
        e["result"] = get(raw, "responseStatus", "code")
        e["correlation_id"] = raw.get("auditID")
        e["details"] = {"stage": raw.get("stage"), "subresource": obj.get("subresource"), "sourceIPs": raw.get("sourceIPs")}
    elif source == "auditd":
        # Expects a parsed audit event, preserving the kernel serial number.
        e["time"] = timestamp(raw.get("time"))
        auid = raw.get("auid")
        if str(auid) in ("-1", "4294967295", "unset"):
            auid = None
        e["actor"] = {"user": auid, "uid": raw.get("uid")}
        e["tty"] = raw.get("tty")
        e["action"] = f"linux.{raw.get('syscall', 'event')}"
        e["target"] = raw.get("exe")
        e["result"] = raw.get("success")
        e["correlation_id"] = raw.get("serial")
        e["details"] = {"pid": raw.get("pid"), "ppid": raw.get("ppid"), "proctitle": raw.get("proctitle")}
    elif source == "rootsh":
        e["actor"] = {"user": raw.get("user"), "uid": raw.get("uid")}
        e["tty"] = raw.get("tty")
        e["action"] = "rootsh.session"
        e["correlation_id"] = raw.get("session_id")
        e["details"] = {"log_ref": raw.get("log_ref"), "phase": raw.get("phase")}
    elif source == "libvirt":
        e["action"] = f"libvirt.{raw.get('operation', 'unknown')}.{raw.get('suboperation', 'unknown')}"
        e["vm_id"] = raw.get("domain_uuid") or raw.get("domain")
        e["target"] = raw.get("domain")
        e["correlation_id"] = raw.get("correlation_id")
        e["details"] = {"phase": raw.get("phase"), "driver": raw.get("driver", "qemu")}
    elif source == "pve":
        e["actor"] = {"user": raw.get("user"), "uid": None}
        e["action"] = f"pve.{raw.get('task', 'event')}"
        e["vm_id"] = raw.get("vm_id")
        e["target"] = raw.get("target")
        e["result"] = raw.get("status")
        e["correlation_id"] = raw.get("upid")
        e["details"] = {"service": raw.get("service")}
    elif source == "containerd":
        event = raw.get("event") or {}
        e["action"] = f"containerd.{raw.get('topic', 'unknown')}"
        e["container_id"] = event.get("container_id") or event.get("id")
        e["namespace"] = raw.get("namespace")
        e["target"] = e["container_id"]
        e["details"] = {"runtime_namespace": raw.get("namespace")}
    else:
        raise ValueError(f"unsupported source: {source}")
    if not e["action"]:
        raise ValueError("missing action")
    canonical = json.dumps({"source": source, "raw": raw}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    e["event_id"] = hashlib.sha256(canonical.encode()).hexdigest()[:32]
    return e


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", choices=["shell", "docker", "k8s_audit", "auditd", "rootsh", "libvirt", "pve", "containerd"])
    p.add_argument("--host", help="collector host identity when absent in event")
    p.add_argument("--input", default="-")
    p.add_argument("--output", default="-")
    args = p.parse_args()
    incoming = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    outgoing = sys.stdout if args.output == "-" else open(args.output, "a", encoding="utf-8")
    failed = 0
    try:
        for line_no, line in enumerate(incoming, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                source = args.source or item["source"]
                raw = item if args.source else item["event"]
                event = normalize(source, raw, args.host)
                outgoing.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                outgoing.flush()
            except (ValueError, KeyError, TypeError) as exc:
                failed += 1
                print(f"line {line_no}: {exc}", file=sys.stderr)
    finally:
        if incoming is not sys.stdin:
            incoming.close()
        if outgoing is not sys.stdout:
            outgoing.close()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
