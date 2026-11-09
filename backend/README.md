# OpenDLP 后端 · Go + PostgreSQL

OpenDLP 管理控制台的服务端：REST API、SSE 实时推送、终端 / 网关数据上报入口，并直接托管 `../frontend` 静态页面（同源部署，无需跨域）。

- Go ≥ 1.24，唯一第三方依赖为 PostgreSQL 驱动 [pgx](https://github.com/jackc/pgx)
- PostgreSQL ≥ 14（测试使用 18）
- 生产部署见 [`../deploy`](../deploy/README.md)（Docker Compose + Caddy 自动 HTTPS）

## 本地开发

### 1. 准备数据库

使用 Homebrew 安装的 PostgreSQL：

```bash
brew services start postgresql@18
```

```bash
createdb opendlp
```

### 2. 启动服务

```bash
cd backend
export OPENDLP_DATABASE_URL=postgres://$(whoami)@127.0.0.1:5432/opendlp
export OPENDLP_AGENT_TOKEN=$(openssl rand -hex 32)   # 终端上报令牌，记下用于 Agent 配置
go run ./cmd/opendlp
```

打开 http://127.0.0.1:8080 ，按页面提示完成**首次初始化**：

1. 在启动日志中找到「一次性初始化令牌」（也可用 `OPENDLP_SETUP_TOKEN` 预先指定）；
2. 填写令牌、超级管理员账号、姓名与口令（≥ 12 位，含大小写字母、数字、符号）；
3. 用身份验证器 App 添加页面显示的密钥，输入 6 位动态码完成绑定并登录。

初始化完成后令牌立即失效。之后建议在「组织与权限」中按三员分立创建系统管理员、安全管理员、审计管理员，并导入组织架构（CSV）。

### 运行模式

| 模式 | 启动参数 | 说明 |
| --- | --- | --- |
| 生产（默认） | — | 数据库为空时只写入基础数据（渠道 / 数据类型字典、内置角色与识别规则、集成清单），业务数据全部来自管理员配置与上报接口 |
| 开发 | `-dev` | 登录动态码与 otpauth 地址打印到日志；允许模拟 SSO / 扫码登录；超级管理员可切换角色视角 |
| 演示 | `-demo` | 空库首次启动时写入演示数据（演示账号口令 `OpenDLP@2026!`，可用 `OPENDLP_DEMO_PASSWORD` 覆盖），并运行检测模拟器。**切勿用于生产** |

演示与开发可组合：`go run ./cmd/opendlp -dev -demo`（建议使用单独的数据库）。

## 配置

所有参数都可以用命令行或同名环境变量设置。

| 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-database-url` | `OPENDLP_DATABASE_URL` | — | **必填**，PostgreSQL 连接串 |
| `-addr` | `OPENDLP_ADDR` | `127.0.0.1:8080` | 监听地址 |
| `-static` | `OPENDLP_STATIC` | `../frontend` | 前端目录；留空只提供 API |
| `-data` | `OPENDLP_DATA_DIR` | `data` | 本地目录（配置快照备份） |
| `-tz` | `OPENDLP_TZ` | `Asia/Shanghai` | 统计报表时区 |
| `-tls-cert` / `-tls-key` | `OPENDLP_TLS_CERT` / `OPENDLP_TLS_KEY` | — | 直接启用 HTTPS |
| `-trust-proxy` | `OPENDLP_TRUST_PROXY` | `false` | 部署在 HTTPS 反向代理之后时开启（同时启用 Secure Cookie） |
| `-log-format` | `OPENDLP_LOG_FORMAT` | `text` | `json` 便于日志平台采集 |
| `-dev` / `-demo` | `OPENDLP_DEV` / `OPENDLP_DEMO` | `false` | 见上表 |
| — | `OPENDLP_AGENT_TOKEN` | — | 终端 / 网关 / 扫描节点上报令牌；不设置则关闭上报接口 |
| — | `OPENDLP_SETUP_TOKEN` | 随机 | 首次初始化令牌 |

其他命令：`opendlp -version`、`opendlp healthcheck`（请求本机 `/readyz`，供容器健康检查）。

## 数据存储

| 数据 | 存储位置 |
| --- | --- |
| DLP 事件 | `incidents` 表（服务端分页、筛选、导出） |
| 外发检测量 | `detections_hourly` 表（按小时 / 渠道 / 数据类型聚合，总览统计实时计算） |
| 审计日志 | `audit_log` 表：SHA-256 哈希链；数据库触发器禁止 UPDATE / DELETE / TRUNCATE |
| 登录会话 | `sessions` 表（仅存令牌摘要），服务重启后会话保持 |
| 策略、规则、角色、管理员、审批单、终端、集成配置等 | `documents` 表中的 JSONB 配置文档（内存工作集，每 2 秒持久化） |

数据库结构在启动时自动迁移（`internal/store/schema.sql`，多实例启动时用咨询锁串行化）。

**数据保留**：后台任务按「系统设置 → 事件记录保留」每日清理已关闭的历史事件；检测量聚合保留 400 天；审计日志不清理。

**备份**：业务数据请使用 `pg_dump` 备份数据库；运维页的「导出配置快照」只保存配置文档。

## 终端 / 网关接入

所有上报接口使用 `Authorization: Bearer $OPENDLP_AGENT_TOKEN`。终端管理页的「终端接入」会展示接入地址与令牌（查看行为记入审计）。

| 接口 | 调用方 | 说明 |
| --- | --- | --- |
| `POST /api/v1/ingest/heartbeat` | 终端 Agent，每 60 秒 | 登记 / 更新终端（主机名为唯一键），响应中返回待执行指令（推送策略、远程扫描、隔离、升级等） |
| `POST /api/v1/ingest/detections` | Agent / 网关 | 批量上报检测结果（≤ 500 条）。`action=allow` 且无 `severity` 仅计入检测量，否则生成 DLP 事件 |
| `POST /api/v1/ingest/nodes` | 检测节点 / 网关 | 节点心跳与指标（CPU、内存、QPS、时延） |
| `POST /api/v1/ingest/approvals` | Agent / 审批门户 | 员工提交外发申请；所在部门有负责人时先进入部门负责人审批 |
| `POST /api/v1/ingest/approvals/{id}/leader` | 企业微信 / 门户 | 回传部门负责人审批结果 |
| `POST /api/v1/ingest/discovery` | 扫描节点 | 回传数据源扫描结果（对象数、敏感对象、分级分布） |

```bash
curl -X POST http://127.0.0.1:8080/api/v1/ingest/heartbeat -H "Authorization: Bearer $OPENDLP_AGENT_TOKEN" -H 'Content-Type: application/json' -d '{"host":"BJ-RD-0001","user":"张伟","ip":"10.10.1.20","os":"Windows 11","osKey":"win","agent":"3.2.1","cpu":12,"mem":40,"disk":55}'
```

```bash
curl -X POST http://127.0.0.1:8080/api/v1/ingest/detections -H "Authorization: Bearer $OPENDLP_AGENT_TOKEN" -H 'Content-Type: application/json' -d '[{"user":"张伟","host":"BJ-RD-0001","channel":"usb","dest":"Kingston DT 64G","dataType":"source","file":"core.zip","size":"12 MB","matches":320,"policyId":"POL-101","action":"block","severity":"critical","ruleIds":["R-101"]}]'
```

渠道取值：`email` `usb` `cloud` `im` `web` `print`；动作：`allow` `audit` `encrypt` `block`；级别：`critical` `high` `medium` `low`。

## 组织架构

「组织与权限 → 导入 CSV」，列顺序：`工号,姓名,部门,职位,邮箱,状态(在职/离职中/已离职),是否部门负责人(是/否)`，后几列可省略。也可调用 `POST /api/v1/iam/employees/import`。员工状态参与风险评分（离职流程中加权），部门负责人用于外发审批第一级。

## 安全设计

- **口令**：PBKDF2-HMAC-SHA256（21 万次迭代、随机盐），常量时间比较；不存在的账号同样执行哈希防止账号枚举。复杂度 ≥ 12 位且含四类字符。
- **登录保护**：同一 IP 5 分钟内最多 10 次尝试；同一账号连续 5 次口令错误锁定 15 分钟；禁用账号无法登录。
- **双因素认证**：RFC 6238 TOTP（±1 时间步），动态码一次性使用；挑战 5 分钟有效、最多 5 次尝试。首次初始化强制绑定。
- **会话**：256 位随机令牌，数据库只存 SHA-256 摘要；HttpOnly + SameSite=Strict（经 HTTPS 时加 Secure）；空闲 30 分钟 / 绝对 12 小时过期；禁用账号、重置 MFA 立即吊销全部会话。
- **CSRF**：写请求必须带 `X-OpenDLP-Request: 1`，且 `Origin` 须与 Host 一致。
- **权限**：每个接口声明「模块 + 操作（view / op / cfg / exp）」并在服务端校验；越权写操作记入审计。权限矩阵保存时校验三员分立冲突，内置角色不可修改。
- **审计**：哈希链 + 数据库触发器双重防篡改；`GET /api/v1/audit/verify` 校验完整性。
- **数据最小化**：`/bootstrap` 只下发当前角色可见的数据；集成密钥以 `******` 返回；新管理员初始口令与 MFA 绑定信息只出现一次。
- **响应头**：CSP（`script-src 'self'`）、`X-Frame-Options: DENY`、`nosniff`、HSTS（HTTPS 时）；静态资源禁止目录列表与隐藏文件。
- **其他**：请求体上限 1 MB；CSV 导出防公式注入；规则正则使用 RE2（线性时间，无 ReDoS）。

## 测试

测试连接真实 PostgreSQL，每个测试使用独立 schema 并在结束后删除：

```bash
OPENDLP_TEST_DATABASE_URL=postgres://$(whoami)@127.0.0.1:5432/opendlp_test go test -race ./...
```

未设置 `OPENDLP_TEST_DATABASE_URL` 时数据库相关测试会跳过。覆盖首次初始化、登录锁定与 CSRF、角色权限与越权审计、会话跨实例保持、RE2 规则校验、三员分立冲突、外发审批状态机、上报与指令下发、组织架构导入、审计日志防篡改（触发器 + 哈希链）、统计聚合（含乱序补报）、TOTP RFC 6238 测试向量等。

## 目录结构

```
backend/
├── cmd/opendlp/main.go      # 入口：配置、迁移、初始化令牌、后台任务、优雅退出
└── internal/
    ├── store/               # PostgreSQL 数据层：配置文档、事件、检测量、审计哈希链、会话、统计
    ├── storetest/           # 测试用独立 schema
    ├── auth/                # PBKDF2 口令、TOTP、会话管理
    ├── api/                 # 路由、鉴权、业务接口、上报接口、SSE、异步任务、报表、后台维护
    ├── seed/                # 基础数据、合规策略模板与演示数据
    └── sim/                 # 演示模式检测模拟器
```

## 已知限制

- 企业 SSO（SAML / OIDC）与扫码登录尚未对接身份提供商，生产模式返回 501；AD / LDAP 同步连接器未内置（使用 CSV 导入）。
- EDM 索引同步、模型训练、规则库在线更新需要检测引擎侧组件，生产模式返回 501。
- 报表输出为可打印 HTML 与 CSV，未内置 PDF / Word 渲染。
- 配置文档由单实例写入；如需多实例水平扩展，需要将配置类数据拆分为独立数据表并加乐观锁。MFA 挑战与异步任务文件保存在内存中，多实例时需会话粘滞。
- 管理员「登录 IP 限制」目前只做记录，未在登录时强制校验。
