#!/usr/bin/env bash
# Source only from an interactive Bash startup file. This is a cooperative PoC.
[[ $- == *i* ]] || return 0
# File mode is used for a mounted container log; opt-in syslog mode is for hosts.
if [[ -z ${INFRA_AUDIT_SINK_FILE:-} ]]; then
    [[ ${INFRA_AUDIT_ENABLE:-0} == 1 ]] || return 0
    command -v logger >/dev/null 2>&1 || return 0
fi
[[ -z ${__INFRA_AUDIT_INSTALLED:-} ]] || return 0
[[ -z $(trap -p DEBUG) ]] || return 0  # Avoid replacing an existing DEBUG trap.
command -v base64 >/dev/null 2>&1 || return 0
__INFRA_AUDIT_INSTALLED=1

__infra_audit_safe() {
    # Restrict metadata so it cannot break the JSON record.
    local value=${1:-}
    [[ $value =~ ^[a-zA-Z0-9._:/@-]*$ ]] && printf '%s' "$value" || printf ''
}

__infra_audit_debug() {
    local prior_status=$? cmd=$1 encoded stamp tty_name actor host payload
    case $cmd in
        __infra_audit_*) return "$prior_status" ;;
    esac
    if [[ -n ${INFRA_AUDIT_SINK_FILE:-} ]]; then
        [[ -f $INFRA_AUDIT_SINK_FILE && -w $INFRA_AUDIT_SINK_FILE ]] || return "$prior_status"
    fi
    __INFRA_AUDIT_SEQ=$(( ${__INFRA_AUDIT_SEQ:-0} + 1 ))
    encoded=$(printf '%s' "$cmd" | base64 | tr -d '\n') || return "$prior_status"
    stamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || return "$prior_status"
    tty_name=$(__infra_audit_safe "$(tty 2>/dev/null)")
    actor=$(__infra_audit_safe "${USER:-unknown}")
    host=$(__infra_audit_safe "${INFRA_AUDIT_HOST:-${HOSTNAME:-unknown}}")
    printf -v payload '{"source":"shell","event":{"time":"%s","user":"%s","uid":"%s","host":"%s","tty":"%s","container_id":"%s","pod":"%s","namespace":"%s","session_id":"%s","sequence":%s,"command_b64":"%s"}}' \
        "$stamp" "$actor" "$EUID" "$host" "$tty_name" \
        "$(__infra_audit_safe "${INFRA_AUDIT_CONTAINER_ID:-}")" \
        "$(__infra_audit_safe "${INFRA_AUDIT_POD:-}")" \
        "$(__infra_audit_safe "${INFRA_AUDIT_NAMESPACE:-}")" \
        "$(__infra_audit_safe "${HOSTNAME:-unknown}:${BASHPID:-$$}")" "$__INFRA_AUDIT_SEQ" "$encoded"
    if [[ -n ${INFRA_AUDIT_SINK_FILE:-} ]]; then
        printf '%s\n' "$payload" >> "$INFRA_AUDIT_SINK_FILE" 2>/dev/null || :
    else
        logger -p local6.info -t infra-audit-shell "$payload" >/dev/null 2>&1 || :
    fi
    return "$prior_status"
}

trap '__infra_audit_debug "$BASH_COMMAND"' DEBUG
