# 本地规则引擎使用说明

- **版本**：v0.3.4
- **日期**：2026-11-17
- **角色**：ToFu

阶段 2 的 agent 对 eBPF `EXEC`、`PIPE`、`DNS`、`SNI` 事件进行本地规则判定。规则保存在 PostgreSQL 中；规则新增或修改后，重启 agent 生效。本阶段只产生告警，不会终止进程或执行其他响应动作。

## 1. 初始化 PostgreSQL

先创建本地数据库用户和数据库（密码请替换为你自己的强密码）：

```bash
sudo -u postgres psql
```

在 psql 提示符中执行：

```sql
CREATE ROLE adr LOGIN PASSWORD '替换为强密码';
CREATE DATABASE adr OWNER adr;
\q
```

在项目根目录设置连接地址并执行规则表迁移：

```bash
export DATABASE_URL='postgres://adr:替换为强密码@127.0.0.1:5432/adr?sslmode=disable'
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/migrations/001_rules.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/migrations/002_rule_event_types.sql
```

密码若包含 `@`、`:`、`/` 等 URI 特殊字符，需要先进行 URL 编码。不要把生产密码提交到仓库。

## 2. 管理规则

使用 `go run ./cmd/adr rules ...` 或已构建的 `adr rules ...`：

```bash
# 列出规则
go run ./cmd/adr rules list

# 新增一条仅用于验证的本地规则
go run ./cmd/adr rules add \
  --id test-sleep \
  --name '测试 sleep 进程' \
  --event-type EXEC \
  --severity low \
  --expression 'Argv[0] matches "(^|/)sleep$"'

# 添加 DNS / SNI / PIPE 测试规则
go run ./cmd/adr rules add --id test-dns-example --name '测试 DNS 查询' --event-type DNS --severity low --expression 'Qname == "example.com"'
go run ./cmd/adr rules add --id test-sni-example --name '测试 TLS SNI' --event-type SNI --severity low --expression 'ServerName == "example.com"'
go run ./cmd/adr rules add --id test-pipe-write --name '测试管道写入' --event-type PIPE --severity low --expression 'Dir == "write" && Len >= 4'

# 确认规则均已保存；list 会包含启用和禁用的规则
go run ./cmd/adr rules list

# 部分更新；未提供的字段保持不变
go run ./cmd/adr rules update --id test-sleep --severity medium
go run ./cmd/adr rules update --id test-sleep --enabled false

# 删除规则
go run ./cmd/adr rules delete --id test-sleep
```

新增、更新时会先校验规则字段并编译表达式；非法规则不会写入数据库。严重级别支持 `low`、`medium`、`high`、`critical`。规则 ID 仅允许字母、数字、点、下划线和连字符。

## 3. 表达式字段

规则的表达式字段按 `event_type` 区分；每条规则只能访问对应事件类型的字段。

| 事件类型 | 可用字段 | 含义 |
|---|---|---|
| `EXEC` | `PID`、`PPID`、`UID`、`GID` | 进程身份信息 |
| `EXEC` | `Comm` | `execve` 系统调用发生前当前进程的名称，通常是调用者（如 shell），不是目标程序名 |
| `EXEC` | `Argv` | eBPF 捕获到的有限个命令行参数 |
| `PIPE` | `PID`、`PPID`、`UID`、`GID`、`Ino`、`Len`、`Dir`、`Data` | 管道进程信息、inode、方向（`read`/`write`）、长度及最多 128 字节的数据 |
| `DNS` | `PID`、`PPID`、`UID`、`GID`、`Qname` | DNS 查询进程信息及查询域名 |
| `SNI` | `PID`、`PPID`、`UID`、`GID`、`ServerName` | TLS 连接进程信息及 ClientHello 中的 SNI |

示例：

```text
Argv[0] matches "(^|/)curl$"
"-o" in Argv
PID == 1234 && Argv[0] matches "(^|/)sleep$"
Dir == "write" && Len > 0
Qname == "example.com"
ServerName == "example.com"
```

eBPF 在 `sys_enter_execve` 读取事件，此时新程序映像还没有替换当前进程，因此 `Comm == "sleep"` 通常不会匹配从 shell 启动的 `sleep`。检测目标命令应优先依据 `Argv[0]` 编写规则。固定槽位会截断较长参数；`Argv` 不是完整、规范化或可信的可执行文件路径。PIPE 的 `Data` 可能含有敏感管道内容，规则可以访问但告警不会输出它。`EXIT`、`FORK` 尚未接入规则引擎；当前字段也不包含父进程路径或文件系统路径。

## 4. 运行 agent 并验证告警

确保 PostgreSQL 已启动、规则表已迁移，并且 `DATABASE_URL` 在 agent 进程环境中可用。构建后在项目根目录启动：

```bash
make build
go build -o /tmp/adr-agent ./cmd/adr
sudo env "DATABASE_URL=$DATABASE_URL" /tmp/adr-agent agent
```

实际启动还需要 Linux eBPF 权限、内核 BTF；加载器当前也需要内核启用 `lsm=bpf`。规则只在 agent 启动时加载，因此新增或修改规则后要重启 agent。保持 agent 运行，在另一个终端分别触发以下事件：

```bash
# EXEC：已有 test-sleep 规则时触发
sleep 1

# PIPE：传输长度大于 eBPF 的最小捕获长度
printf 'pipe-test-data\n' | cat >/dev/null

# DNS：查询规则匹配的域名
getent ahostsv4 example.com

# SNI：建立 TLS 连接，发送 example.com 的 ClientHello
curl --noproxy '*' --connect-timeout 5 --max-time 10 -I https://example.com
```

若相应规则已启用且事件被内核捕获，agent 应打印对应规则 ID 的告警（`test-sleep`、`test-pipe-write`、`test-dns-example`、`test-sni-example`）。DNS 查询可能被本机缓存；若没有 DNS 告警，可在 `curl` 命令触发解析，或在系统安装了 `dig` 时执行 `dig example.com`。也可用 `dig @<DNS服务器地址> example.com` 直接发起 UDP DNS 查询。SNI 告警需要成功建立 TLS 连接并在可见的 ClientHello 中带有 SNI；DoH/ECH 等方式可能无法识别。DNS/SNI 测试需要网络及相应工具；curl 直连失败时，需在允许出站 HTTPS 的网络中测试。事件头中的 `TsNs` 是内核启动后的单调时钟纳秒值，告警按 `ts_ns` 输出，不将它错误解释为日历时间。

agent 会继续在终端输出告警，并将**告警行**追加写入 `/tmp/adr-alerts.log`；其他普通事件不会写进该文件。查看文件：

```bash
sudo tail -f /tmp/adr-alerts.log
```

可通过 `ADR_ALERT_LOG` 指定其他路径。使用 sudo 启动时也要传入该变量，例如：

```bash
sudo env "DATABASE_URL=$DATABASE_URL" ADR_ALERT_LOG=/tmp/adr-alerts.log /tmp/adr-agent agent
```

日志文件以追加方式打开，新建时权限为 `0600`。若指定路径无法打开或写入失败，agent 会报告错误并退出，不会静默丢弃告警。

## 5. 外部规则与隐私

本地规则默认将 `source` 记为 `local`。导入 Sigma 等公开规则时，应保存上游 ID、作者、许可证和来源链接；先检查规则依赖的数据字段并验证误报，再启用。命中告警会带上非空的规则作者。

规则表达式可访问 `Argv`，因此只应导入并启用经过审核的规则。当前告警不输出完整 argv；规则输入不会暴露环境变量。
