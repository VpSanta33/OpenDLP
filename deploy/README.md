# OpenDLP 生产部署

`docker-compose.yml` 包含三个服务：

| 服务 | 说明 |
| --- | --- |
| `db` | PostgreSQL 16，数据卷 `pgdata` |
| `app` | OpenDLP（Go 后端 + 前端），distroless 镜像、非 root 运行，内置健康检查 |
| `caddy` | 反向代理，自动申请 / 续期 HTTPS 证书，对外暴露 80 / 443 |

## 部署步骤

前提：Docker 与 Docker Compose 插件；对外访问时域名已解析到本机。

```bash
cd deploy
cp .env.example .env
```

编辑 `.env`：设置 `POSTGRES_PASSWORD`、`OPENDLP_AGENT_TOKEN`（`openssl rand -hex 32`）与 `OPENDLP_DOMAIN`。

```bash
docker compose up -d --build
```

```bash
docker compose logs app | grep -A2 初始化令牌
```

浏览器打开 `https://你的域名`，使用日志中的初始化令牌创建超级管理员并绑定 MFA。

## 运维

查看状态与健康检查：

```bash
docker compose ps
```

数据库备份（建议每日定时执行并异地保存）：

```bash
docker compose exec -T db pg_dump -U opendlp -Fc opendlp > opendlp-$(date +%F).dump
```

恢复：

```bash
docker compose exec -T db pg_restore -U opendlp -d opendlp --clean < opendlp-2026-11-09.dump
```

升级：拉取新代码后执行 `docker compose up -d --build app`，数据库结构在启动时自动迁移。

## 说明

- 应用日志为 JSON 格式（`docker compose logs app`），可接入日志平台。
- 只有 Caddy 对外暴露端口；`app` 以 `OPENDLP_TRUST_PROXY=true` 运行，Cookie 带 Secure 标记。
- 如果使用已有的负载均衡器或 Nginx，可删除 `caddy` 服务，但需保证：终止 HTTPS、转发 `X-Forwarded-For`、保留原始 Host，并对 `/api/v1/stream` 关闭响应缓冲（SSE）。
- 本仓库在开发环境中未能实际构建镜像（开发机未运行 Docker 守护进程），首次部署时请留意构建输出。

## 终端 Agent

1. 服务端设置 `OPENDLP_AGENT_TOKEN`（注册令牌），并在「系统设置 → 告警通知 → 控制台访问地址」填写终端可访问的 HTTPS 地址。
2. 在 `backend/` 下执行 `scripts/build-agent.sh <版本>`，产物位于 `backend/bin/agent/`（附 SHA256SUMS）。
3. 按平台使用 `deploy/agent/` 中的 systemd 单元、launchd plist 或 `install-windows.ps1` 安装；也可在控制台「终端管理 → 终端接入」查看带令牌的安装步骤。
4. 建议通过软件分发平台（SCCM / Jamf / 统信软件中心）批量下发二进制与配置文件，配置文件权限保持 0600。
