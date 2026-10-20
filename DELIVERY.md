# 交付清单与接入顺序

这是一份可审查的配置/PoC 包，项目位置为 `~/ai/codex/infrastructure-audit/`。本次只创建项目文件，**没有写入目标机器的 `/etc`、没有读取生产审计日志、没有启动服务**。目标环境的现状请看 `CURRENT_STATUS.md`，并在相应 Linux/PVE 节点运行 `scripts/audit_status.sh` 获取只读清单。

## 文件对应的部署位置

| 项目文件 | 目标位置或用途 |
|---|---|
| `scripts/bash_audit.sh` | `/etc/profile.d/99-infra-audit.sh`；只对加载它的交互式 Bash 生效。 |
| `config/rsyslog-forward-tls.conf.in` | 渲染后成为发送端 `/etc/rsyslog.d/70-infra-audit.conf`，默认部署脚本选择此模板。 |
| `config/rsyslog-receiver-tls.conf.in` | 中央接收端模板，需填发送方证书名称。 |
| `config/rsyslog-host-inputs.conf.in` | 可选主机输入：auditd 和 Debian/RHEL 认证日志，渲染后为 `/etc/rsyslog.d/71-infra-audit-host-inputs.conf`。 |
| `config/rsyslog-forward.conf.in`、`config/rsyslog-receiver.conf` | 纯 TCP 实验室模板，不适合跨不可信网络使用。 |
| `config/auditd.rules.example` | Linux auditd 规则示例，需按架构/UID 规划后再放入 `/etc/audit/rules.d/`。 |
| `config/k8s-audit-policy.yaml` | Kubernetes API Server Audit policy 示例，需按集群方式配置 API Server。 |
| `scripts/libvirt-hook-example.sh` | QEMU hook 示例，不由部署脚本自动安装。 |
| `src/normalize.py`、`src/collect_file.py` | 原始 JSONL 映射与文件持续转换 PoC。 |
| `config/event.schema.json`、`examples/events.jsonl` | 统一字段定义与**模拟**事件；示例不是目标环境当前日志。 |
| `scripts/manage.py` | 默认 dry run 的发送端配置部署/回滚脚本。 |
| `scripts/audit_status.sh` | 在目标 Linux/PVE 节点运行的只读现状检查。 |

## 数据流

1. **宿主机交互式 Bash**：管理员显式设置 `INFRA_AUDIT_ENABLE=1` 后，profile 脚本用 `logger` 发出 `infra-audit-shell` 原始 JSON。节点 Rsyslog 应已有 `imuxsock` 或 `imjournal` 输入；发送模板将该 tag 转发，接收端写入 `received-shell-raw.jsonl`。再在接收端用 `collect_file.py` 将其转换为统一字段。原始消息不能防止用户伪造。
2. **容器内交互式 Bash**：提供可写共享卷中的既有文件路径 `INFRA_AUDIT_SINK_FILE`。profile 脚本追加原始 JSONL；`collect_file.py` 转为统一事件，写入 `normalized.jsonl`。Rsyslog `imfile` 转发该文件。容器用户能写共享文件就可能篡改它，应用于辅助取证。
3. **控制面和运行时**：Docker Events、Kubernetes API Audit、auditd 解析结果、rootsh 会话引用、libvirt hook、PVE 任务和 containerd 事件均可作为 `normalize.py` 的输入。当前交付是字段映射和接入示例；各平台的长期订阅、断线恢复、原始日志解析及权限部署尚需目标环境实现。

## 先在隔离目录验证

```sh
cd ~/ai/codex/infrastructure-audit
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 src/normalize.py --input examples/events.jsonl --output /tmp/infra-audit-example.jsonl
mkdir -p /tmp/infra-audit-root
python3 scripts/manage.py deploy --root /tmp/infra-audit-root --remote logs.example.com --port 6514
python3 scripts/manage.py deploy --root /tmp/infra-audit-root --remote logs.example.com --port 6514 --apply
python3 scripts/manage.py rollback --root /tmp/infra-audit-root --apply
```

`manage.py` 默认选 TLS。实验室若确实使用纯 TCP，需要明确添加 `--transport tcp-lab`，并使接收端端口与 `--port` 一致。安装动作不会创建证书、审计日志目录、服务，也不会重启 Rsyslog。

如果只需要把服务器原始审计日志发送到 Rsyslog，按 [服务器转发说明](SERVER_FORWARDING.md) 选择 `--host-input debian|rhel|custom`。该选项会增加 auditd 和认证日志的 `imfile` 输入；接收端按来源分文件保存。本轮没有数据展示功能。

## profile 文件模式的端到端 PoC

先在测试目录准备一个可写文件，再进入会读取该脚本的交互式 Bash。退出后运行文件转换程序：

```sh
mkdir -p /tmp/infra-audit-demo
touch /tmp/infra-audit-demo/raw-shell.jsonl
INFRA_AUDIT_SINK_FILE=/tmp/infra-audit-demo/raw-shell.jsonl \
  bash --noprofile --rcfile scripts/bash_audit.sh -i
# 在新 Bash 中输入：echo audit-demo，然后 exit
python3 src/collect_file.py \
  --input /tmp/infra-audit-demo/raw-shell.jsonl \
  --output /tmp/infra-audit-demo/normalized.jsonl \
  --state /tmp/infra-audit-demo/shell.state \
  --rejects /tmp/infra-audit-demo/rejected.jsonl
```

目标节点长期运行时可加 `--follow` 并交由服务管理器监管。PoC 使用轮询及 inode/offset 状态：轮转旧文件后继续写入的尾部可能漏掉；输出落盘与状态更新之间崩溃可能重复，需按 `event_id` 去重。生产还需完善限流、权限、磁盘配额和告警。

中央接收端的宿主机 logger 原始文件可同样用 `collect_file.py` 转换，输入为 `received-shell-raw.jsonl`，输出应使用**另一个文件**（例如 `received-shell-normalized.jsonl`），并使用独立的 state/rejects 文件。不要把输出写回输入，否则会形成循环。

## Rsyslog 配置审查

发送端 TLS 文件需要远端名称与端口，以及 `/etc/infra-audit/tls/ca.pem`、`client.pem`、`client-key.pem`。接收端 TLS 模板要把 `__CLIENT_NAME__` 改为允许的客户端证书名称，并提供 CA、服务端证书和私钥。两端需要相互信任的证书及相同的 TLS/端口设置。Rsyslog 运行用户应能读取证书、输入文件、写队列状态；接收端应能写 `/var/log/infra-audit/`。

在目标机器审查并验证**完整** Rsyslog 配置后，再由管理员决定是否加载：

```sh
rsyslogd -N1
```

这里的 `imfile` 只监控 `/var/log/infra-audit/normalized.jsonl`。`PersistStateInterval=100` 让 Rsyslog 保存读取位置；磁盘队列与接收端保留策略还要按吞吐量调整。中央接收端把规范化事件和宿主机 shell 原始事件分开保存；接收端不应仅凭消息内 `host` 或 `user` 字段信任发送方身份，应校验证书及来源。

## 回滚和边界

`python3 scripts/manage.py rollback --root <目标根目录>` 先显示计划，添加 `--apply` 才恢复原文件。目标 `/` 还需 `--allow-live`。如果部署后文件被别人改过，脚本拒绝覆盖。它只回滚自己管理的 profile 与发送端 Rsyslog 文件；auditd、Kubernetes、libvirt 和 PVE 示例未自动安装，因此没有对应自动回滚动作。

profile 采集只覆盖加载相应启动配置的交互式 Bash。非交互进程、直接 exec、`sh`/`ash`、无 Shell 容器、绕过或篡改该脚本的会话均不能保障。请结合 API Audit、宿主机 auditd、运行时事件和独立审计存储判断完整性。
