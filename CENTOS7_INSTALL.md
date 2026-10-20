# 全新 CentOS 7 主机：审计采集与 Rsyslog 转发

本脚本面向 **CentOS Linux 7 x86_64** 主机，在本机启用 Linux auditd 规则，转发 `/var/log/audit/audit.log` 与 `/var/log/secure`，并让新开启、确实加载 `/etc/profile.d` 的交互式 Bash 通过 `logger` 发送命令观察记录。发送端只负责采集和转发；中央 Rsyslog 需事先配置接收、证书和防篡改存储。Docker、Kubernetes、KVM/libvirt、PVE 需要各自的控制面/运行时采集器，安装本脚本不会自动覆盖这些平台。

CentOS Linux 7 已于 **2024-06-30** 停止维护；新机的默认 yum 镜像可能失效。脚本不会改写 yum 源，请先准备可信的内部镜像或迁移到受支持系统。生产传输默认双向 TLS，缺少证书就会停止安装；不自动降级为明文 TCP。

## 准备

1. 在目标主机确认 `/etc/os-release` 为 CentOS 7、架构为 `x86_64`，且以 root 执行。目标应是尚未使用本项目文件的新主机；脚本发现同名目标文件会拒绝覆盖。
2. 中央 Rsyslog 已监听 TCP 6514，采用 TLS 并信任客户端证书。其证书 DNS 名须与 `--peer` 一致；`--remote` 是连接地址，可与 `--peer` 不同。接收端模板见 `config/rsyslog-receiver-tls.conf.in`，应先在接收端按其版本完成配置与验收。
3. 在主机上安全放置 CA 证书、客户端证书、无密码客户端私钥。脚本复制到 `/etc/infra-audit/tls/`，私钥权限为 `0600`。不要把私钥提交到仓库。
4. 确认 6514/TCP 出站可达、主机与接收端时间同步，并给 `/var/log/audit` 和 Rsyslog 工作目录预留空间。检查 `/etc/rsyslog.conf` 是否已有重复转发规则，避免重复采集。

## 安装

在仓库根目录运行：

```sh
sudo bash scripts/install_centos7.sh install \
  --remote logs.example.com --port 6514 \
  --peer logs.example.com \
  --ca /root/audit-certs/ca.pem \
  --cert /root/audit-certs/client.pem \
  --key /root/audit-certs/client-key.pem
```

脚本调用 `yum` 安装 `audit`、`rsyslog`、`rsyslog-gnutls`，写入专用 auditd 规则、Rsyslog 配置和两个 profile 文件，执行 `rsyslogd -N1`，加载审计规则并启动/重启相应服务。若配置检查或启用过程失败，会尝试移除本次文件与专用运行时规则。脚本本身不写入清空或锁定规则集的指令；`augenrules` 仍会按目标机现有规则文件重新加载，因此部署前要审查现有策略。审计规则根据 `/etc/login.defs` 的 `UID_MIN` 捕获登录用户的 `execve`，并观察身份、sudo、SSH、audit 配置改动。审计量在活跃多用户主机上可能较高。

隔离实验室若没有证书，可明确选择明文 TCP：

```sh
sudo bash scripts/install_centos7.sh install --remote 192.0.2.10 --transport tcp-lab --port 514
```

该模式不会验证接收方身份或加密命令与认证日志，不应用于生产网络。

## 核验与卸载

```sh
sudo bash scripts/install_centos7.sh status
sudo auditctl -l | grep infra_c7_
sudo auditctl -s
sudo rsyslogd -N1
sudo logger -p local6.info -t infra-audit-shell '{"source":"shell","event":{"command_b64":"ZWNobyB0ZXN0"}}'
```

在新的交互式 Bash 中执行无敏感信息的命令，再到中央接收端检查 `infra-audit-auditd:`、`infra-audit-auth:`、`infra-audit-shell:` 三类消息。只在发送端看到服务运行和本地日志，**不能证明中央已收到**。`auditctl -s` 的 `lost` 应不持续增长；断网时还要检查 Rsyslog 队列和磁盘空间。

```sh
sudo bash scripts/install_centos7.sh uninstall
```

卸载会校验本项目安装文件的 SHA256；文件被其他管理员修改后会拒绝删除。它移除专用文件与当前运行的专用 auditd 规则，重载 Rsyslog；已安装的软件包、原有日志和服务保留。若内核审计规则已被其他策略锁定，必须先解除锁定或重启，脚本不会强行清空其他规则。安装失败后的包安装与 systemd 自启动设置也不会自动撤销，应按变更记录检查。

## 覆盖边界

- `auditd` 的 `execve` 捕获外部程序启动，不能完整记录 Bash 内建命令、进程内部行为或执行结果。规则只覆盖 64 位 ABI；32 位兼容进程需另审视是否追加 b32 规则。
- profile 脚本只对确实加载 `/etc/profile.d` 的**交互式 Bash** 会话生效。非交互进程、直接 exec、`sh`/`ash`、无 shell 容器、绕过/篡改 profile 都不能保证。它不能替代 auditd、受控 rootsh 会话或控制面审计。
- `/var/log/secure` 提供 SSH、sudo、PAM 等认证日志；实际字段取决于服务配置。`rsyslog imfile` 按行发送原始 auditd 与 auth 日志，接收端要按 audit serial/时间等字段关联，不能把每行当作独立完整操作。
- 若目标环境有 SELinux 拒绝、Rsyslog 权限限制、审计规则锁定或高频日志导致队列满，需查看服务日志并处理；脚本不会关闭 SELinux、防火墙或修改 `auditd.conf`。

资料：[CentOS 7 生命周期](https://www.centos.org/centos-linux/)、[RHEL 7 auditd 启动方式](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-starting_the_audit_service)、[Rsyslog imfile](https://docs.rsyslog.com/doc/configuration/modules/imfile.html)、[Rsyslog TLS 客户端](https://docs.rsyslog.com/doc/tutorials/tls_cert_client.html)。
