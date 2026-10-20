#!/usr/bin/env bash
# CentOS 7 host audit collector. Run locally as root after reviewing the project.
set -Eeuo pipefail
umask 077

STATE=/var/lib/infra-audit-centos7
RSYS=/etc/rsyslog.d/70-infra-audit-centos7.conf
RULES=/etc/audit/rules.d/70-infra-audit-centos7.rules
ENABLE=/etc/profile.d/98-infra-audit-enable.sh
PROFILE=/etc/profile.d/99-infra-audit.sh
TLS_DIR=/etc/infra-audit/tls
FILES=("$RSYS" "$RULES" "$ENABLE" "$PROFILE")
TLS_FILES=("$TLS_DIR/ca.pem" "$TLS_DIR/client.pem" "$TLS_DIR/client-key.pem")
KEYS=(infra_c7_exec infra_c7_identity infra_c7_privilege infra_c7_ssh infra_c7_audit)
STARTED=0

usage() {
  cat <<'EOF'
用法:
  bash scripts/install_centos7.sh install --remote 日志服务器DNS名 --peer 证书DNS名 \
    --ca CA证书 --cert 客户端证书 --key 客户端私钥 [--port 6514]
  bash scripts/install_centos7.sh install --remote 地址 --transport tcp-lab [--port 514]
  bash scripts/install_centos7.sh status
  bash scripts/install_centos7.sh uninstall

默认双向 TLS。tcp-lab 仅用于隔离实验室。接收端需要事先配置并开放端口。
EOF
}
die() { echo "错误: $*" >&2; exit 1; }
log() { echo "[infra-audit] $*"; }
valid_host() { [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9._:-]*$ && $1 != *..* ]]; }
has_our_rules() { auditctl -l 2>/dev/null | grep -q 'infra_c7_'; }
delete_live_rules() {
  local key
  for key in "${KEYS[@]}"; do auditctl -D -k "$key" >/dev/null 2>&1 || :; done
}
cleanup_failed() {
  local rc=$?
  trap - ERR EXIT
  if (( STARTED )); then
    log "安装未完成，移除本次创建的文件和审计规则"
    rm -f -- "${FILES[@]}" "${TLS_FILES[@]}"
    delete_live_rules
    augenrules >/dev/null 2>&1 || :
    systemctl restart rsyslog >/dev/null 2>&1 || :
    rm -rf -- "$STATE"
  fi
  exit "$rc"
}
trap cleanup_failed EXIT

[[ $# -gt 0 ]] || { usage; exit 2; }
operation=$1
shift
[[ $EUID -eq 0 ]] || die "请以 root 运行"
[[ -r /etc/os-release ]] || die "缺少 /etc/os-release"
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == centos && ${VERSION_ID:-} == 7* ]] || die "仅支持 CentOS Linux 7"
[[ $(uname -m) == x86_64 ]] || die "当前规则仅支持 x86_64"
command -v systemctl >/dev/null || die "需要 systemd"

case "$operation" in
  status)
    [[ $# -eq 0 ]] || die "status 不接受参数"
    [[ -d $STATE ]] && log "已安装" || log "未安装"
    for service in auditd rsyslog; do
      systemctl is-active "$service" || :
    done
    if command -v auditctl >/dev/null; then auditctl -s || :; fi
    if [[ -f $RSYS ]]; then rsyslogd -N1; fi
    exit 0
    ;;
  uninstall)
    [[ $# -eq 0 ]] || die "uninstall 不接受参数"
    [[ -f $STATE/manifest ]] || die "未找到安装记录"
    command -v sha256sum >/dev/null || die "缺少 sha256sum"
    while read -r expected path; do
      [[ -f $path && ! -L $path ]] || die "文件丢失或变成符号链接: $path"
      [[ $(sha256sum "$path" | awk '{print $1}') == "$expected" ]] ||
        die "文件已被修改，拒绝覆盖: $path"
    done < "$STATE/manifest"
    # A locked audit policy cannot be changed before reboot.
    if auditctl -s | grep -Eq '^enabled[[:space:]]+2$'; then
      die "内核审计规则已锁定；需解除锁定或重启后再卸载"
    fi
    while read -r _ path; do rm -f -- "$path"; done < "$STATE/manifest"
    delete_live_rules
    augenrules >/dev/null
    rsyslogd -N1
    systemctl restart rsyslog
    rm -rf -- "$STATE"
    log "已卸载本项目文件和当前运行的专用审计规则；软件包与原有服务保留"
    exit 0
    ;;
  install) ;;
  *) usage; exit 2 ;;
esac

remote= peer= ca= cert= key= transport=tls port=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote|--peer|--ca|--cert|--key|--transport|--port)
      [[ $# -ge 2 ]] || die "$1 缺少值"
      case "$1" in
        --remote) remote=$2 ;; --peer) peer=$2 ;; --ca) ca=$2 ;;
        --cert) cert=$2 ;; --key) key=$2 ;; --transport) transport=$2 ;;
        --port) port=$2 ;;
      esac
      shift 2 ;;
    *) die "未知参数: $1" ;;
  esac
done
[[ ! -e $STATE && ! -L $STATE ]] || die "已有安装记录；请先运行 status 或 uninstall"
for path in /etc/infra-audit "$TLS_DIR"; do
  [[ ! -L $path ]] || die "拒绝使用符号链接目录: $path"
done
for path in "${FILES[@]}" "${TLS_FILES[@]}"; do
  [[ ! -e $path && ! -L $path ]] || die "目标文件已存在，拒绝覆盖: $path"
done
valid_host "$remote" || die "--remote 只能是 DNS 名称或 IP 地址"
[[ $transport == tls || $transport == tcp-lab ]] || die "--transport 仅支持 tls/tcp-lab"
if [[ -z $port ]]; then
  [[ $transport == tls ]] && port=6514 || port=514
fi
[[ $port =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) ||
  die "--port 必须是 1..65535"
if [[ $transport == tls ]]; then
  valid_host "$peer" || die "TLS 模式需要 --peer（接收端证书 DNS 名）"
  for path in "$ca" "$cert" "$key"; do
    [[ -f $path && ! -L $path ]] || die "TLS 文件缺失或为符号链接: $path"
  done
  command -v openssl >/dev/null || die "TLS 模式需要 openssl"
  openssl x509 -in "$ca" -noout -checkend 0 >/dev/null || die "CA 证书无效或已过期"
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null || die "客户端证书无效或已过期"
  openssl pkey -in "$key" -passin pass: -noout >/dev/null 2>&1 ||
    die "客户端私钥不可读取或需要密码"
  cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
  key_pub=$(openssl pkey -in "$key" -passin pass: -pubout -outform DER | sha256sum)
  [[ $cert_pub == "$key_pub" ]] || die "客户端证书与私钥不匹配"
fi
if command -v auditctl >/dev/null && auditctl -s | grep -Eq '^enabled[[:space:]]+2$'; then
  die "内核审计规则已锁定，无法加载新规则"
fi
if grep -Eh '^[[:space:]]*-e[[:space:]]+2([[:space:]]|$)' /etc/audit/rules.d/*.rules /etc/audit/audit.rules >/dev/null 2>&1; then
  die "现有审计规则文件包含 -e 2，加载后会锁定，拒绝安装"
fi
if command -v auditctl >/dev/null && has_our_rules; then
  die "检测到同名审计规则，拒绝重复安装"
fi
uid_min=$(awk '$1=="UID_MIN" {print $2; exit}' /etc/login.defs)
[[ $uid_min =~ ^[0-9]+$ ]] || die "无法读取 /etc/login.defs 的 UID_MIN"

log "检查软件包；CentOS 7 已停止维护，若 yum 源失效，请先配置可信的内部镜像"
packages=(audit rsyslog)
[[ $transport != tls ]] || packages+=(rsyslog-gnutls)
yum install -y "${packages[@]}"
for cmd in auditctl augenrules rsyslogd logger; do
  command -v "$cmd" >/dev/null || die "缺少命令: $cmd"
done
mkdir -p "$STATE" "$TLS_DIR"
STARTED=1
if [[ $transport == tls ]]; then
  install -m 0644 "$ca" "${TLS_FILES[0]}"
  install -m 0644 "$cert" "${TLS_FILES[1]}"
  install -m 0600 "$key" "${TLS_FILES[2]}"
fi

cat > "$RSYS" <<EOF
# Managed by infrastructure-audit/scripts/install_centos7.sh.
module(load="imfile")
EOF
if [[ $transport == tls ]]; then
  cat >> "$RSYS" <<EOF
\$DefaultNetstreamDriverCAFile $TLS_DIR/ca.pem
\$DefaultNetstreamDriverCertFile $TLS_DIR/client.pem
\$DefaultNetstreamDriverKeyFile $TLS_DIR/client-key.pem
EOF
fi
cat >> "$RSYS" <<EOF
ruleset(name="infra_c7_forward") {
  action(type="omfwd" target="$remote" port="$port" protocol="tcp"
         template="RSYSLOG_SyslogProtocol23Format"
EOF
if [[ $transport == tls ]]; then
  cat >> "$RSYS" <<EOF
         StreamDriver="gtls" StreamDriverMode="1"
         StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="$peer"
EOF
fi
cat >> "$RSYS" <<'EOF'
         action.resumeRetryCount="-1"
         queue.type="LinkedList" queue.size="10000"
         queue.filename="infra_c7_forward" queue.maxDiskSpace="1g"
         queue.saveOnShutdown="on")
}
input(type="imfile" File="/var/log/audit/audit.log"
      Tag="infra-audit-auditd:" Facility="local6" Severity="info"
      PersistStateInterval="100" ruleset="infra_c7_forward")
input(type="imfile" File="/var/log/secure"
      Tag="infra-audit-auth:" Facility="local6" Severity="info"
      PersistStateInterval="100" ruleset="infra_c7_forward")
if $syslogtag startswith "infra-audit-shell:" then {
  call infra_c7_forward
  stop
}
EOF
chmod 0644 "$RSYS"

cat > "$RULES" <<EOF
# Managed by infrastructure-audit. Does not clear or lock existing rules.
-a always,exit -F arch=b64 -S execve -F auid>=$uid_min -F auid!=4294967295 -k infra_c7_exec
-a always,exit -F arch=b64 -S execve -F auid=0 -k infra_c7_exec
-w /etc/passwd -p wa -k infra_c7_identity
-w /etc/group -p wa -k infra_c7_identity
-w /etc/shadow -p wa -k infra_c7_identity
-w /etc/sudoers -p wa -k infra_c7_privilege
-w /etc/sudoers.d/ -p wa -k infra_c7_privilege
-w /etc/ssh/sshd_config -p wa -k infra_c7_ssh
-w /etc/audit/ -p wa -k infra_c7_audit
EOF
chmod 0640 "$RULES"
printf '%s\n' 'export INFRA_AUDIT_ENABLE=1' > "$ENABLE"
chmod 0644 "$ENABLE"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -m 0644 "$SCRIPT_DIR/bash_audit.sh" "$PROFILE"

rsyslogd -N1
systemctl enable auditd rsyslog
if ! systemctl is-active --quiet auditd; then service auditd start; fi
augenrules --load
auditctl -l | grep -q 'infra_c7_exec' || die "审计规则未加载"
systemctl restart rsyslog
systemctl is-active --quiet rsyslog || die "rsyslog 未启动"
for path in "${FILES[@]}"; do sha256sum "$path"; done > "$STATE/manifest"
if [[ $transport == tls ]]; then
  for path in "${TLS_FILES[@]}"; do sha256sum "$path"; done >> "$STATE/manifest"
fi
chmod 0600 "$STATE/manifest"
STARTED=0
log "安装完成。请在中央 Rsyslog 核对 auditd、auth、shell 三类事件。"
log "已启用新的交互式 Bash profile；当前 shell 不会追溯加载。"
