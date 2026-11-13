# NetSentinel

NetSentinel 面向实验室、小型服务器和教学环境，使用自主开发的 Go 独立规则引擎分析授权导入的 Nginx、Linux SSH 日志，通过 React Web 平台管理规则、执行离线分析并处置告警。

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
| 当前阶段 | 工程基础已建立，Count 可独立运行，Web 与健康检查可联调，业务增量继续推进 |

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
  cmd/server/           迁移、服务启动、健康检查命令与优雅关闭
  internal/             配置、API、SQLite 仓储与角色契约
  migrations/           内嵌编号 SQL 与迁移摘要
frontend/src/           React + TypeScript，app/features/shared 分层
deploy/                 多阶段镜像与 Nginx 同源代理
compose.yml             migrate、api、web 与持久化卷
AGENTS.md               智能体行为与业务不变量
DESIGN.md               中文界面、视觉 token 与交互规范
```

基础代码已实现规则严格解码、带类型谓词、Count、确定性证据与指纹、输入顺序与资源校验、SQLite WAL/外键/事务迁移、HTTP 健康检查、请求标识，以及真实服务状态工作台。根目录规则约束后续实现，模块可通过现有 CI 独立检查。

Distinct、Sequence、日志导入、登录与会话、业务权限、规则管理、异步任务、告警处置和通知仍按增量计划开发。Web 对应页面展示模块状态，业务 API 随功能接入。当前数据库仅含迁移记录、用户、会话、审计基础表，管理员初始化随登录功能实现。本次交付为基础框架，v0.1 业务验收继续按计划推进。

## 本地启动

需要 Go 1.27、Node.js 24。Go 模块独立维护，后端通过本地 `replace` 引用引擎。

在第一个终端初始化数据库并启动后端。

```sh
cd backend
go mod download
go run ./cmd/server -migrate
go run ./cmd/server
```

后端默认监听 `127.0.0.1:8080`，数据目录为启动工作目录下的 `./data`。可通过 `NETSENTINEL_ADDR` 和 `NETSENTINEL_DATA_DIR` 覆盖。后续启动使用同一数据目录，已有迁移 SQL 的摘要变化将使启动失败，结构变更通过新增编号迁移完成。

在第二个终端启动 Web。

```sh
cd frontend
npm ci
npm run dev
```

访问 [本地 Web](http://127.0.0.1:5173)，Vite 将 `/api` 代理到本地后端。工作台的“重新检查”读取实际 API、数据库迁移与目录可写状态。后端提供以下公开接口。

| 接口 | 行为 |
| --- | --- |
| `GET /api/v1/health/live` | 进程存活，返回 200 |
| `GET /api/v1/health/ready` | 数据库与迁移、运行目录检查，返回 200 或 503 |

响应使用 `data` / `error` 与 `request_id`，原始目录及内部错误只保留在服务端。

## Compose 启动

在根目录运行以下命令，迁移容器成功后启动 API，API 就绪后启动 Web。

```sh
docker compose up --build -d --wait
docker compose ps -a
```

访问 [容器 Web](http://127.0.0.1:8088)。Web 端口默认绑定本机，可在根目录 `.env` 中设置 `.env.example` 的 `NETSENTINEL_WEB_PORT`。SQLite 使用 `netsentinel-data` 命名卷，停止应用使用 `docker compose down`。升级前停止应用并备份命名卷，迁移后进行就绪检查。

## 开发验证

分别在 `engine/` 和 `backend/` 执行以下命令。PowerShell 中保持覆盖率参数的引号。

```sh
gofmt -l .
go vet ./...
go test -race -covermode=atomic '-coverprofile=coverage.out' ./...
go build ./...
```

在 `frontend/` 执行 `npm ci`、`npm run typecheck`、`npm test`、`npm run build`。根目录执行 `npx --yes markdownlint-cli2@0.24.0`。基础测试覆盖 Count 阈值和闭合窗口、分组、重跑确定性、并发运行、配额、取消、接收器失败、规则校验、迁移约束和健康响应，执行记录见[基础框架交付记录](Documentation/Implementation/基础框架交付记录.md)。

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

远端仓库为 [Double-Cloth/NetSentinel](https://github.com/Double-Cloth/NetSentinel)，默认分支为 `main`。2026-11-13 实际查询该分支的生效规则返回空列表，保护规则需由维护者落实。团队协作仍按贡献指南通过开发分支和 PR、人工 Review、`CI 结果` 检查集成，Projects 与 Releases 按详细计划书推进。

基础 CI 在 push、PR 和手动触发时执行文档检查，并按 `engine/`、`backend/`、`frontend/` 模块接入状态启用 Go/Web 检查。仓库提供缺陷、功能、任务、需求变更 Issue 表单及 PR 模板，协作约定与本地检查命令见 [贡献指南](CONTRIBUTING.md)。
