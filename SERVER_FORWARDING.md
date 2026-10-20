# Linux 服务器审计：仅采集并发送到 Rsyslog

本轮范围是**日志从服务器到中央 Rsyslog 的传输**。不做查询界面、报表、数据展示或集中分析。项目仍处于隔离配置阶段，没有改动任何目标服务器。

## 发送什么

| 来源 | 发送端接入 | 接收端文件 | 注意 |
|---|---|---|---|
| auditd | `imfile` 读取 `/var/log/audit/audit.log` | `received-auditd-raw.log` | 保留原始多行 audit 记录；Rsyslog 用户必须能读该文件。规则示例见 `config/auditd.rules.example`，未自动安装。 |
| SSH / sudo / PAM 等认证日志 | Debian/Ubuntu `/var/log/auth.log` 或 RHEL 系 `/var/log/secure` | `received-auth-raw.log` | 具体内容取决于发行版及认证配置。由 `--host-input` 选择，避免同时读两份。 |
| 交互式 Bash profile | 显式设置 `INFRA_AUDIT_ENABLE=1`，经 `logger` 发送 | `received-shell-raw.jsonl` | 仅补充覆盖已加载脚本的 Bash，会被绕过；不代表执行成功。 |
| rootsh | 系统已安装且 syslog tag 以 `rootsh` 开头时转发 | `received-rootsh-raw.log` | 仅覆盖实际通过 rootsh 的会话；内容可能含敏感终端输出。 |
| PVE 管理守护进程 | 本机 syslog 已接入且 tag 以 `pvedaemon`/`pveproxy` 开头时转发 | `received-pve-raw.log` | 不保证包含完整任务日志；需在 PVE 节点核对实际 tag/日志路径。 |
| 已规范化事件 | `imfile` 读取 `/var/log/infra-audit/normalized.jsonl` | `received.jsonl` | 由其他采集器写入；输入文件不存在时不会有此类事件。 |

Docker Events、Kubernetes API Audit、containerd Events、libvirt hook 等仍按主项目 `README.md` 的设计接入；本轮没有把它们伪装成已经部署的服务器日志源。

## 配置生成与部署前检查

`scripts/manage.py` 默认 dry run、默认 TLS，且只管理项目对应的 `/etc/profile.d/` 和 `/etc/rsyslog.d/` 文件。先在临时根目录检查生成结果：

```sh
mkdir -p /tmp/infra-audit-root
python3 scripts/manage.py deploy --root /tmp/infra-audit-root \
  --remote logs.example.com --port 6514 --host-input debian --apply
cat /tmp/infra-audit-root/etc/rsyslog.d/70-infra-audit.conf
cat /tmp/infra-audit-root/etc/rsyslog.d/71-infra-audit-host-inputs.conf
python3 scripts/manage.py rollback --root /tmp/infra-audit-root --apply
```

RHEL 系把 `--host-input debian` 改成 `rhel`。其他发行版使用 `--host-input custom --auth-log /绝对/日志/路径`。选择 `none` 时不安装 auditd/auth 文件输入。目标实际根目录 `/` 需要另加 `--allow-live --apply`；本次**没有执行**。生产发送端还需准备 CA/客户端证书与私钥；接收端模板 `config/rsyslog-receiver-tls.conf.in` 需填允许的客户端证书名称并准备服务端证书。可用 `--transport tcp-lab` 生成纯 TCP 实验室配置。

在目标 Linux 机器先检查 auditd、Rsyslog 的现有配置、日志权限和服务状态；运行 `sh scripts/audit_status.sh` 可读到工具、服务与 auditctl 状态。请检查是否已有 auditd/认证日志转发策略，以免双重采集。审核完整配置后运行 `rsyslogd -N1`；再由管理员决定是否启用或重载。需要检查中央存储目录权限及磁盘容量。`auditd.rules.example` 只作规则评审，加载之前应核对现有规则、架构、UID_MIN 和审计负载。

## 到达验证（无展示系统）

1. 发送端确认 `rsyslogd -N1` 通过，Rsyslog 服务运行；auditd `auditctl -s` 的 `lost` 不增长。初次启用 `imfile` 可能回读已有日志，需预留队列和接收空间。
2. 在隔离环境产生一条 SSH 登录成功/失败、一条授权的 sudo 操作，以及一条触发 auditd 规则的命令。分别核对中央 `received-auth-raw.log` 与 `received-auditd-raw.log` 的主机、时间和原始内容。
3. 对宿主机 profile 模式，在明确启用后开启新的交互式 Bash 并执行无敏感信息的测试命令；核对 `received-shell-raw.jsonl`。先确认目标发行版的 `/etc/profile` 会加载 `/etc/profile.d`。
4. 在隔离环境断开中央 Rsyslog，观察发送端队列文件与恢复后的实际补发；检查磁盘占用、重复和丢失。当前磁盘辅助队列在正常重启时可保存内存数据，但不能保证进程被强杀或主机断电时零丢失。TLS 两端应相互验证证书身份。
5. 审计日志可能含账号、IP、命令行和终端输出；限制传输、存储权限。不要把客户端消息里的 `host`、`user` 当作经过证明的身份。

此配置只解决**送达链路**，不等于等保三级审计项验收完成。长期运行、日志保护和备份、留存期限、采集进程保护等需要另行实施和取证。

## 依据

- [Linux auditctl 手册](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [RHEL 9 auditd 配置说明](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Rsyslog imfile](https://docs.rsyslog.com/doc/configuration/modules/imfile.html) 与 [omfwd](https://docs.rsyslog.com/doc/configuration/modules/omfwd.html)
