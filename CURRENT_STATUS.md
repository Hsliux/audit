# 当前审计状态说明

本仓库在 **2026-10-20** 的本地工作环境是 macOS（Darwin），不是 Linux、Kubernetes 控制平面、KVM 或 PVE 节点。这里未检测到 `auditctl`、`rsyslogd`、`virsh`、`pvesh`、`rootsh`；本地有 Docker 和 `kubectl` 客户端，但没有连接或读取任何服务端状态。因此**没有目标环境的真实审计事件、服务状态或配置清单**，不能把 `examples/events.jsonl` 当成当前生产审计信息。

本机只读检查的原始输出保存在 `reports/current-audit-status-local.txt`。

要获取某台目标 Linux/PVE 主机的当前状态，在该主机本地运行只读脚本：

```sh
sh scripts/audit_status.sh
```

它列出本机工具、预期配置文件、systemd 服务状态和 `auditctl` 当前状态/规则；不读取命令历史、日志正文，也不访问 Docker/Kubernetes API。`auditctl` 输出可能需要管理员权限。脚本不会改变系统配置。若要核对实际事件，应由有权限的管理员在目标主机按保密要求检查 `/var/log/audit/audit.log`、Kubernetes API Audit 文件、PVE 任务日志和 Rsyslog 接收文件，并对敏感字段进行处理。
