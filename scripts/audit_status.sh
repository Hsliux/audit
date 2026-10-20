#!/bin/sh
# Read-only local inventory. Does not contact Docker or Kubernetes APIs.
set -u
printf 'audit-status time_utc=%s os=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$(uname -s)"

for tool in auditctl ausearch rootsh rsyslogd docker containerd kubectl virsh pvesh pvenode; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf 'tool %-12s present\n' "$tool"
    else
        printf 'tool %-12s absent\n' "$tool"
    fi
done

for path in \
    /etc/profile.d/99-infra-audit.sh \
    /etc/rsyslog.d/70-infra-audit.conf \
    /etc/rsyslog.d/71-infra-audit-host-inputs.conf \
    /etc/audit/rules.d/50-infra-audit.rules \
    /var/log/audit/audit.log \
    /var/log/auth.log \
    /var/log/secure \
    /var/log/infra-audit/normalized.jsonl; do
    if [ -e "$path" ]; then
        printf 'path %-48s present\n' "$path"
    else
        printf 'path %-48s absent\n' "$path"
    fi
done

if command -v systemctl >/dev/null 2>&1; then
    for service in auditd rsyslog docker containerd libvirtd virtqemud pvedaemon pveproxy; do
        status=$(systemctl is-active "$service" 2>/dev/null || :)
        printf 'service %-12s %s\n' "$service" "${status:-unknown}"
    done
fi

if command -v auditctl >/dev/null 2>&1; then
    printf '\n[auditctl -s]\n'
    auditctl -s 2>&1 || printf 'auditctl status unavailable (check privileges/kernel support)\n'
    printf '\n[auditctl -l]\n'
    auditctl -l 2>&1 || printf 'auditctl rules unavailable (check privileges/kernel support)\n'
fi
