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

## 终端 Agent（opendlp-agent）

跨平台用户态 Agent（Windows / macOS / Linux，含 ARM64 与龙芯 LoongArch64），无需内核驱动，采用「事后检测 + 隔离」：

- **接入**：使用注册令牌（`OPENDLP_AGENT_TOKEN`）换取终端独立凭据，本地以 0600 权限保存；之后请求使用 `Authorization: Agent <id>:<secret>`，主机名以凭据为准。控制台可单独吊销，吊销后 Agent 用注册令牌自动重新注册（彻底停用需同时轮换注册令牌）。
- **策略**：心跳（60 秒）返回最新策略包版本，变化时按 ETag 拉取并缓存到本地；控制台不可达时使用缓存继续检测与隔离。
- **监控范围**：可移动介质（macOS `/Volumes`、Linux `/media` 与 `/run/media` 挂载点、Windows 可移动盘符）与配置的目录（网盘同步目录 → `cloud`、IM 文件目录 → `im` 等）。介质插入或 Agent 启动时已有的文件只建立基线，之后新增 / 修改的文件在大小与修改时间稳定后检测。
- **检测与处置**：与服务端共用 `internal/detect` 引擎（RE2 正则、关键词、文件类型，身份证 / 银行卡校验位，Office 与 zip 文本提取）。命中「阻断」策略的文件移入本地隔离区（附元数据），原位置留下「.DLP隔离说明.txt」；「加密」策略在用户态无法实现，按审计记录并注明；严格管控终端（UEBA）审计升级为阻断。
- **上报**：命中敏感内容的文件均上报控制台；网络不可用时写入本地离线队列，恢复后批量补报。
- **指令**：`push`（同步策略）、`scan`（全量扫描监控目录）执行并回传结果；`isolate` / `upgrade` 明确返回不支持（请使用 NAC / 软件分发平台）。

```bash
scripts/build-agent.sh 3.3.0          # 交叉编译到 bin/agent/，并生成 SHA256SUMS
opendlp-agent run -server https://dlp.corp.example -token <注册令牌> -watch cloud=~/Library/CloudStorage
opendlp-agent status                  # 注册状态、策略版本、离线队列、隔离区、监控目录
opendlp-agent scan                    # 一次性全量检测
```

配置文件与服务安装见 `deploy/agent/`（`agent.example.json`、systemd 单元、launchd plist、Windows 计划任务安装脚本）。控制台「终端管理 → 终端接入」按平台给出安装步骤。macOS 需通过 MDM 授予「完全磁盘访问权限」。

## 告警与定时报表

- **告警通道**（「运维与集成」中配置，「系统设置 → 告警通知」开关）：SMTP 邮件（STARTTLS / TLS，服务器不支持 STARTTLS 时默认拒绝明文发送）、企业微信群机器人、钉钉机器人（支持加签）、Syslog（RFC 5424 + CEF，UDP / TCP）转发 SIEM。
- 严重 / 高危事件实时推送，中低危按「告警汇总频率」合并；审计日志实时转发 SIEM；终端 / 节点离线、外发审批、审计链校验失败也会通知。每个通道独立队列与重试（立即 / 5 秒 / 30 秒），投递统计显示在集成卡片上；「测试连接」会真实发送一条测试消息。演示模式只模拟投递。
- **定时报表**：执行周期支持 `每日 HH:MM`、`每周X HH:MM`、`每月 N 日 HH:MM`（1-28）、`每季度首日 HH:MM`。到期生成上一完整周期的报表、归档，并通过 SMTP 以附件发送给接收人邮箱；执行结果记录在定时报表上。停机错过的周期在启动后补执行一次。

## 终端 / 网关接入（共享令牌）

网关、邮件 MTA 等第三方系统使用 `Authorization: Bearer $OPENDLP_AGENT_TOKEN`。终端管理页的「终端接入」会展示接入地址与令牌（查看行为记入审计）。

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
- **口令生命周期**：新建管理员与被重置口令的账号首次登录必须修改口令；超过「系统设置 → 管理员口令有效期」（默认 90 天）同样强制修改，期间只开放改密接口。修改成功后吊销该账号其他会话。
- **登录来源限制**：按账号配置允许的 IP / CIDR，在口令校验、动态码校验与每次请求时校验，超出范围的已有会话立即失效。
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

未设置 `OPENDLP_TEST_DATABASE_URL` 时数据库相关测试会跳过。覆盖终端 Agent 端到端流程（注册、策略同步、基线、U 盘隔离、阈值、网盘审计、指令、凭据吊销重注册、离线队列补报、严格管控）、告警投递（企业微信 / SMTP / Syslog）、定时报表周期计算与执行、强制改密与口令过期、登录来源限制、首次初始化、登录锁定与 CSRF、角色权限与越权审计、会话跨实例保持、RE2 规则校验、三员分立冲突、外发审批状态机、上报与指令下发、组织架构导入、审计日志防篡改（触发器 + 哈希链）、统计聚合（含乱序补报）、TOTP RFC 6238 测试向量等。

## 目录结构

```
backend/
├── cmd/opendlp/main.go      # 入口：配置、迁移、初始化令牌、后台任务、优雅退出
├── cmd/opendlp-agent/       # 终端 Agent 入口（run / enroll / status / scan）
├── scripts/build-agent.sh   # Agent 交叉编译
└── internal/
    ├── agent/               # 终端 Agent：注册、心跳、策略缓存、目录 / 介质轮询、隔离、离线队列
    ├── detect/              # 共享检测引擎与文本提取（服务端规则测试与 Agent 共用）
    ├── notify/              # 告警通道：SMTP、企业微信、钉钉、Syslog CEF
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
- 终端 Agent 为用户态实现：对 U 盘 / 同步目录是「写入后检测并隔离」，无法在写入前拦截，也无法管控浏览器上传、邮件客户端、打印与剪贴板；这些渠道需网关或内核级驱动。网络隔离与自动升级需借助 NAC 与软件分发平台。
- Agent 以轮询方式发现文件变化（默认 5 秒），监控目录过大（> 20 万文件）时只处理前 20 万个文件。
- 文本提取支持纯文本、Office Open XML（docx / xlsx / pptx）与一层 zip，其余二进制格式只提取可打印 UTF-8 片段；不支持 PDF 文本层与 OCR。
