# NetSentinel

NetSentinel 面向实验室、小型服务器和教学环境。项目以授权 Nginx、Linux SSH 日志的定时拉取、独立 Go 规则引擎分析和站内告警为主流程，通过 React Web 平台查看来源状态与证据。

## 项目章程摘要

| 项目 | 内容 |
| --- | --- |
| 业务目标 | 将原始日志转化为可解释、可复现、可追溯的安全线索 |
| 核心交付 | Count、Distinct、Sequence 引擎，日志解析，规则版本，分析任务，告警证据与处置 |
| 参与角色 | admin、analyst、auditor，外部集成为飞书自定义机器人 |
| 技术约束 | Go、React + TypeScript、SQLite、单机 Docker Compose |
| 团队 | A 负责需求与解析，B 负责引擎，C 负责服务与运维，D 负责 Web 与质量，可兼任 |
| 过程模型 | 需求基线约束下的增量迭代，按 v0.1、v0.2、v0.3 形成三个可运行交付 |
| 选型理由 | 检测正确性和日志格式存在早期风险，先用最小纵向业务验证，再增加规则能力与产品流程，每轮保留测试、评审与回顾证据 |
| 成功标准 | 三类规则结果正确，重复分析幂等，三角色权限有效，完整业务可复现，课程资料与发布记录对应 |
| 当前阶段 | v0.1.0 开发中，自动采集、跨批次 Count 分析及站内告警代码已接入；受控 SFTP、Compose 业务验收和人工评审待完成 |

## 主流程修订计划

根据第 10 周教师建议及[变更 #58](https://github.com/Double-Cloth/NetSentinel/issues/58)，v0.1.0 的出口是“配置授权日志源 → 定时自动拉取 → 不可变批次 → R-001 自动分析 → 站内告警与证据”。手工上传用于补录与测试，人工处置和飞书通知在后续版本。采集网络访问由 backend 承担，引擎读取固定快照。工作包状态及剩余验收见 [v0.1.0 交付索引](Documentation/Implementation/v0.1.0_交付索引.md)。

## 当前实现与目录

```text
engine/                 独立 Go module，仅依赖标准库
  event/                统一事件、类型化字段、输入校验
  predicate/            有界表达式、类型检查与预编译正则
  rule/                 严格 JSON、规范化、快照摘要、不可变编译结果
  detector/             Count 闭合窗口与阈值周期
  finding/              解释、全部证据、逻辑指纹与结果摘要
  runtime/              迭代器、接收器、配额、取消与运行统计
  testdata/rules/        R-001 确定性规则样例
backend/                Go HTTP 服务，进程装配与业务包分离
  cmd/server/           迁移、管理员初始化、服务与健康检查
  internal/             配置、API、SQLite 仓储与身份会话
  migrations/           内嵌编号 SQL 与迁移摘要
  testdata/logs/        确定性 SSH/Nginx 原始日志测试夹具
frontend/src/           React + TypeScript，app/features/shared 分层
deploy/                 多阶段镜像与 Nginx 同源代理
models/                 UML 图源、SVG 与合成 API 契约夹具
Documentation/          课程原文、需求基线、规划、ADR 与实施记录
compose.yml             migrate、api、web 与持久化卷
AGENTS.md               智能体行为与业务不变量
DESIGN.md               中文界面、视觉 token 与交互规范
```

代码已实现规则严格解码、带类型谓词、Count、确定性证据与指纹、输入顺序与资源校验、SQLite WAL/外键/事务迁移、基础身份与健康检查。后端新增授权源目录、只读 SFTP 定位读取、SSH/Nginx 解析、不可变原文与批次、自动任务和站内告警。跨批次 Count 使用来源前缀重放和触发批次所有权，具体边界见 [ADR-010](Documentation/ADR/010_跨批次回放与采集实现.md)。

当前 Web 支持基础登录、刷新恢复会话、退出登录、健康检查、来源状态与重试、批次诊断、自动任务及告警证据查询。Distinct、Sequence、规则草稿与发布治理、完整 RBAC、人工处置及飞书通知在后续增量交付。来源错误、积压和数据过期单独显示；无告警不能解释为无风险。

## 本地启动

需要 Go 1.27.4 及 Node.js 24。Go 模块独立维护，后端通过本地 `replace` 引用引擎。

在第一个终端初始化数据库并启动后端。

```sh
cd backend
go mod download
go run ./cmd/server -migrate
read -rs -p '管理员密码: ' admin_password
printf '%s\n' "$admin_password" | go run ./cmd/server -init-admin admin
unset admin_password
go run ./cmd/server
```

首次初始化在空用户表中创建管理员。用户名为 3—32 位小写字母、数字或下划线，密码至少 12 个字符且最多 72 个 UTF-8 字节。上面的密码输入使用 Bash，PowerShell 可用 `(Read-Host '管理员密码' -MaskInput) | go run ./cmd/server -init-admin admin`。已有管理员时直接启动服务。

后端默认监听 `127.0.0.1:8080`，从 `backend/` 启动时数据保存在 `backend/data/`。可通过 `NETSENTINEL_ADDR` 和 `NETSENTINEL_DATA_DIR` 覆盖。后续启动使用同一数据目录，结构变更通过新增编号迁移完成。

在第二个终端启动 Web。

```sh
cd frontend
npm ci
npm run dev
```

访问 [本地 Web](http://127.0.0.1:5173)，用初始化的账号登录。Vite 将 `/api` 代理到本地后端。工作台的“重新检查”读取 API、数据库迁移与目录可写状态。

| 接口 | 行为 |
| --- | --- |
| `GET /api/v1/health/live` | 进程存活，返回 200 |
| `GET /api/v1/health/ready` | 数据库与迁移、运行目录检查，返回 200 或 503 |
| `POST /api/v1/auth/login` | 校验同源请求与用户名密码，建立会话 |
| `GET /api/v1/auth/me` | 使用会话 Cookie 查询当前用户、权限与 CSRF token |
| `POST /api/v1/auth/logout` | 校验 Origin 和 CSRF 后撤销会话，返回 204 |
| `GET/POST /api/v1/log-sources` | 查看来源，admin 从部署授权目录启用来源 |
| `PATCH /api/v1/log-sources/{id}` | admin 按 `row_version` 修改周期、解析参数与启停 |
| `POST /api/v1/log-sources/{id}/test` | admin 只读连接测试与前 100 行解析预览，不推进断点 |
| `POST /api/v1/log-sources/{id}/retry` | admin 排队采集重试；尝试结果在 `/attempts` 查询 |
| `GET /api/v1/datasets`、`GET /api/v1/datasets/{id}/lines` | 查看不可变批次、原始行与诊断 |
| `GET /api/v1/tasks`、`GET /api/v1/alerts` | 查看自动任务及告警；`/alerts/{id}/evidence` 查询原始证据 |
| `GET /api/v1/rules/R-001`、`POST /api/v1/rules/validate` | 查看固定规则、校验 Count 规则 JSON |

响应使用 `data` / `error` 与 `request_id`，原始目录及内部错误只保留在服务端。

### 配置授权日志源

部署者先准备只读 SFTP 账号、固定主机公钥、私钥文件及稳定追加的日志导出。源端还需提供一个只读代次文件，内容为 1—64 位 ASCII 字母、数字、下划线或连字符，可有一个尾随换行。启用期间同一代次的已写前缀不可改；轮转或截断会明确失败，不能自动续采。真实日志须先按部署方要求脱敏并取得授权。

Compose 部署时将私钥放在本地 `deploy/credentials/`，确保容器用户 10001 可读；复制 `deploy/sources.example.json` 为 `deploy/sources.local.json`，填写授权条目。目录文件只保存私钥的容器内路径，不保存私钥内容；两个本地路径均由 `.gitignore` 排除。条目示例中的主机公钥须替换为实际核验值：

```json
[
  {
    "id": "lab-ssh",
    "name": "实验室 SSH 脱敏导出",
    "address": "sftp.example.invalid:22",
    "username": "netsentinel-readonly",
    "key_file": "/run/netsentinel/credentials/reader.key",
    "host_public_key": "ssh-ed25519 <经独立渠道核验的公钥>",
    "log_path": "/export/auth.log",
    "generation_path": "/export/auth.generation",
    "format": "ssh-rfc3339",
    "source_host": "server-node-01"
  }
]
```

在根目录 `.env` 中设置 `NETSENTINEL_SOURCE_CATALOG_FILE=./deploy/sources.local.json`，重新启动 Compose。管理员在“系统设置”选择授权条目、设置采集周期并启用。默认的 `sources.example.json` 是空目录，启动后不会访问任何远端。直接运行后端时，可用 `NETSENTINEL_SOURCE_CATALOG` 指向受控 JSON 文件，并将 `key_file` 写成该机器的绝对路径。

v0.1 固定 R-001 对 SSH 失败事件自动分析，Nginx 批次可查看但不运行 SSH 规则。Count 跨批次按同一来源的固定历史前缀重放；新增事件时间倒退时拒绝发布，避免静默改变历史窗口。单次运行上限为 100 万事件，超限任务显式失败。首次部署建议用授权合成源验证四条失败位于前批次、第五条位于后批次的告警与五条证据，再测试断线、半行和重试。

## Compose 启动

在根目录运行以下命令，迁移容器成功后启动 API，API 就绪后启动 Web。

```sh
docker compose up --build -d --wait
docker compose ps -a
```

首次部署时，在 Bash 中通过标准输入初始化首个管理员。

```sh
read -rs -p '管理员密码: ' admin_password
printf '%s\n' "$admin_password" | docker compose exec -T api /app/server -init-admin admin
unset admin_password
```

访问 [容器 Web](http://127.0.0.1:8088)。Web 端口默认绑定本机，可在根目录 `.env` 设置 `NETSENTINEL_WEB_PORT`。使用 HTTPS 反向代理或非本机浏览器 Origin 时，设置 `NETSENTINEL_PUBLIC_ORIGIN` 为浏览器地址的协议、主机和端口，例如 `https://netsentinel.example`。SQLite 使用 `netsentinel-data` 命名卷，停止应用使用 `docker compose down`。升级前停止应用并备份命名卷，迁移后进行就绪检查。

## 开发验证

分别在 `engine/` 和 `backend/` 执行以下命令。PowerShell 中保持覆盖率参数的引号。

```sh
gofmt -l .
go vet ./...
go test -race -covermode=atomic '-coverprofile=coverage.out' ./...
go build ./...
```

在 `frontend/` 执行 `npm ci`、`npm run typecheck`、`npm test`、`npm run build`。根目录执行 `npx --yes markdownlint-cli2@0.24.0`。基础测试覆盖 Count 阈值和闭合窗口、分组、重跑确定性、并发运行、配额、取消、接收器失败、规则校验、迁移约束和健康响应，执行记录见[基础框架交付记录](Documentation/Implementation/基础框架交付记录.md)。

## 第 11 周需求交付

[SRS v1.0 发布候选](Documentation/Requirements/SRS_v1.0.md)、[追溯矩阵 v0](Documentation/Requirements/追溯矩阵_v0.md)、[用例图](Documentation/Requirements/用例图.md)、[变更管理](Documentation/Requirements/变更管理.md)及[评审与发布记录](Documentation/Requirements/评审与发布记录.md)对应 Issue #6。按用户 2026-11-25 最新指令，第 11 周任务以其他成员批准 PR、CI 通过并合入 main 为完成条件，不再要求教师签字。来源冲突与技术待办保留供成员评审及后续实现跟踪；`srs-v1.0.0` Release 作为合并后的归档，不作为额外完成门槛。候选需求不代表产品能力已实现。

## 文档导航

| 文档 | 阅读内容 |
| --- | --- |
| [项目实施指导](Documentation/NetSentinel_项目实施指导.md) | 原始目标、范围、团队与课程交付约束 |
| [课程要求](Documentation/Requirement/) | 课程原始要求与八次检查点 |
| [详细项目计划书](Documentation/Planning/01_详细项目计划书.md) | 工作分解、依赖、负责人、迭代、风险、课程资料与配置管理 |
| [功能与需求规格](Documentation/Planning/02_功能与需求规格.md) | 22 个功能用例、2 个非功能用例、角色权限、用户故事及业务状态 |
| [独立规则引擎详细设计](Documentation/Planning/03_独立规则引擎详细设计.md) | 事件模型、规则格式、8 条具体规则、算法、窗口边界、证据与版本语义 |
| [前后端与数据实现设计](Documentation/Planning/04_前后端与数据实现设计.md) | 包依赖、解析、任务事务、表结构、API 契约、Web 页面及部署流程 |
| [测试验收与需求追溯](Documentation/Planning/05_测试验收与需求追溯.md) | 规则测试向量、集成与验收、性能方案、分析类、模型计划及课程映射 |

以上规划文档形成于 2026-11-13，由 Codex 辅助起草。阈值、工期、容量和性能预算均属于设计提案，需通过真人调研、团队评审与实测形成基线。框架选型与依赖记录见 [ADR-008](Documentation/ADR/008_基础工程与依赖选型.md)。

## 协作与发布

需求与变更通过 Issue 管理，开发分支经 PR、人工 Review 和 CI 合并至 `main`。需求基线使用 `srs-v1.0.0`，产品增量使用 `v0.1.0`、`v0.2.0`、`v0.3.0`，避免版本命名混淆。每名成员至少主讲一次并完成至少 10 个有效合并 PR，保留两次正式抽样代码评审和两轮以上迭代回顾。

远端仓库为 [Double-Cloth/NetSentinel](https://github.com/Double-Cloth/NetSentinel)，默认分支为 `main`。2026-11-26 核验确认经典分支保护已生效，要求通过 PR、至少一项批准评审、处理完全部讨论并通过 `CI 结果` 检查，禁止强制推送和删除 `main`。协作流程见 [贡献指南](CONTRIBUTING.md)，任务进度见 [Project #4](https://github.com/users/Double-Cloth/projects/4)。

基础 CI 在 push、PR 和手动触发时执行文档检查，并按 `engine/`、`backend/`、`frontend/` 模块接入状态启用 Go/Web 检查。仓库提供缺陷、功能、任务、需求变更 Issue 表单及 PR 模板，协作约定与本地检查命令见 [贡献指南](CONTRIBUTING.md)。
