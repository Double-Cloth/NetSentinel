# 合成日志测试夹具

本目录只包含确定性合成数据，用于后续日志解析、采集和端到端测试。主机名、账号、PID、端口与请求均为虚构值；IP 仅使用 RFC 5737 的 IPv4 文档网段和 RFC 3849 的 IPv6 文档前缀。

当前仓库尚未实现原始日志解析、自动采集及 Web 告警链路。这些文件现在用于锁定输入契约和 R-001 预期，不能据此宣称端到端链路已经通过。现有规则引擎继续使用规范化 `Event` 测试。

## 夹具与预期

| 文件 | 格式 | 预期 |
| --- | --- | --- |
| `ssh_r001_hit.log` | SSH RFC3339 | 同一组在 240 秒内出现 5 次失败，R-001 命中一次 |
| `ssh_r001_no_hit.log` | SSH RFC3339 | 第 5 次位于 300 秒加 1 微秒，闭合窗口中最多 4 次，不命中 |
| `ssh_mixed_users.log` | SSH RFC3339 | root 3 次、admin 2 次，按用户分组后不命中 |
| `ssh_invalid_user.log` | SSH RFC3339 | 独立 `Invalid user` 行忽略；5 条 `Failed ... invalid user` 形成一次命中 |
| `ssh_dirty.log` | SSH RFC3339 | 包含成功、应忽略消息、无效 IP 和无效时间；不产生 R-001 命中 |
| `ssh_rfc3164.log` | SSH RFC3164 | 使用清单中的 `year=2026`、`timezone=+08:00` 解释，5 次失败命中一次 |
| `nginx_combined.log` | Nginx combined | 包含正常、query、敏感路径、5xx、IPv6 和无效 request |

`manifest.json` 固定每个文件的行数、SHA-256、时间参数和预期命中数。校验测试仅验证夹具契约，不替代生产解析器测试。

```powershell
Set-Location backend
go test ./internal/testfixtures -v
```
