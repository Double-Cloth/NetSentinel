# 贡献指南

## 开始任务

阅读 [README](README.md)、[详细项目计划书](Documentation/Planning/01_详细项目计划书.md) 及相关设计。项目根目录或工作目录存在 `AGENTS.md`、`DESIGN.md` 时，按其约束执行。

通过 Issue 记录需求、缺陷、开发或文档任务、需求变更。关联 UC/US、WP、规则或测试编号，填写负责人、验收标准及目标增量。任务一般拆分为 4—12 人时，依赖任务通过 Issue 关联。

## 分支与评审

功能、修复和文档分支沿用 `feat/<issue>-<topic>`、`fix/<issue>-<topic>`、`docs/<issue>-<topic>`，仓库配置使用 `chore/<issue>-<topic>`。提交说明写明意图，可使用 `feat`、`fix`、`docs`、`test`、`ci`、`chore` 类型。

PR 填写变更目的、关联 Issue、验证记录和兼容性影响，邀请至少一名其他成员人工 Review。远端默认分支和集成分支均为 `main`；新建 PR 时以 `main` 为目标分支，并在 `CI 结果` 通过、讨论处理完成及人工批准后合并。

需求基线变更先提交需求变更 Issue，记录原需求、新需求、原因、工期及数据/API/测试影响、审批人和生效版本。需求基线使用 `srs-v1.0.0`，产品增量使用 `v0.1.0`、`v0.2.0`、`v0.3.0`。AI 辅助工作按实际记录使用范围、人工核验和修改或拒绝情况。

## CI 与本地验证

[CI 配置](.github/workflows/ci.yml) 在 push、PR 和手动触发时运行。每次执行文档检查并检测 `engine/go.mod`、`backend/go.mod` 和 `frontend/package.json`，已存在的模块自动加入检查。三个基础模块现已接入，文档与 Go/Web 检查共同执行。

Markdown 使用以下命令检查。

```sh
npx --yes markdownlint-cli2@0.24.0
```

[Markdown 配置](.markdownlint-cli2.jsonc) 保留长中文段落和现有表格写法，原始课程资料 `Documentation/Requirement/` 作为引用资料排除。后续维护的项目文档均参与检查。

Go 版本从各模块的 `go.mod` 读取。模块接入后，分别在 `engine/` 和 `backend/` 执行以下命令。

```sh
gofmt -l .
go vet ./...
go test -race -covermode=atomic '-coverprofile=coverage.out' ./...
go build ./...
git diff --exit-code -- go.mod go.sum
```

`gofmt -l .` 输出应为空。CI 保存各 Go 模块覆盖率报告 14 天，覆盖声明按测试计划记录实际范围与结果。

前端接入约定为 Node.js 24、npm 和提交到仓库的 `frontend/package-lock.json`。在 `frontend/package.json` 提供 `typecheck`、`test` 和 `build` 脚本，`test` 在 `CI=true` 环境下单次运行。在 `frontend/` 执行以下命令。

```sh
npm ci
npm run typecheck
npm test
npm run build
git diff --exit-code -- package.json package-lock.json
```

本地测试前将环境变量 `CI` 设为 `true`，或使用测试工具的单次运行方式。前端初始化若采用其他工具链，在同一 PR 更新工作流与本指南。当前配置涵盖文档、Go/Web 基础检查及 Compose 构建与烟测。业务集成和端到端验收随对应增量接入。

## GitHub 配置维护

Issue 表单和 PR 模板放在 `.github/`。Dependabot 每周一北京时间 09:00 检查 GitHub Actions、两个 Go module 与 npm 依赖更新，React 相关依赖成组提交更新 PR。

GitHub 仓库以 `main` 为默认集成分支。2026-11-13 查询分支生效规则返回空列表，维护者需落实保护配置。团队约定通过 PR、至少一名其他成员批准、处理完全部讨论并通过 `CI 结果` 检查后集成。Milestone 按三个增量创建，Projects 使用 Backlog、Ready、In Progress、In Review、Done。

测试夹具使用授权脱敏日志或确定性合成数据。提交前检查差异和凭据，运行数据及构建输出按 `.gitignore` 管理。
