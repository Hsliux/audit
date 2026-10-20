#!/bin/sh
# Example only: deploy as a separate qemu.d hook after version compatibility review.
# Do not read domain XML or call libvirt from inside a hook.
set -eu
sink=${INFRA_AUDIT_HOOK_SINK:-}
[ -n "$sink" ] && [ -f "$sink" ] && [ -w "$sink" ] || exit 0
domain=$1 operation=$2 phase=$3
# Arguments from libvirt must be escaped; Python is deliberately required here.
python3 - "$sink" "$domain" "$operation" "$phase" <<'PY' || :
import json, sys
from datetime import datetime, timezone
path, domain, operation, phase = sys.argv[1:]
event = {"source":"libvirt","event":{"time":datetime.now(timezone.utc).isoformat(),
         "domain":domain,"operation":operation,"phase":phase,"driver":"qemu"}}
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(event, separators=(",", ":")) + "\n")
PY
exit 0
