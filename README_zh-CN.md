# aliyun-auto-cert

[![Test](https://github.com/yin1999/aliyun-auto-cert/actions/workflows/test.yml/badge.svg)](https://github.com/yin1999/aliyun-auto-cert/actions/workflows/test.yml)

[English](README.md) | [简体中文](README_zh-CN.md)

这是一个用于自动更新阿里云 CDN 上部署的 TLS 证书的简单工具。

## 用法

将名称为 [`.env-dist`](.env-dist) 的文件拷贝到 `.env`，并编辑它，填写你的域名、邮箱地址和 access key 和 secret。

```ini
FULL_DOMAIN=domain.example.com
EMAIL=user@example.com
ACCESS_KEY=ak
ACCESS_SECRET=sk
# ACCOUNT FILE 应为 json 文件或环境变量名（如 `env:ACCOUNT_JSON`）
ACCOUNT_FILE=account.json
MUST_LOAD_ACCOUNT=false # 如果你不想意外创建新的 ACME 账号，请将其设置为 true
```

> [!NOTE]
> 阿里云提供的 access key 和 secret 需要有 `AliyunCDNFullAccess` 和 `AliyunDNSFullAccess` 权限。

然后，运行以下命令来检查并更新证书：

```bash
# 设置环境变量
export $(grep -v '^#' .env | xargs)

# 运行程序
./auto-cert
# ACME 账号会被保存在由 `ACME_ACCOUNT_FILE` 环境变量指定的文件中
```

### 服务模式

你也可以将程序以服务的模式运行（在 Linux 上使用 [_systemd_](https://systemd.io/)），以周期性地检查和更新证书

在 `/etc/systemd/system/` 目录下创建名为 `aliyun-auto-cert.service` 的服务文件：

```ini
[Unit]
Description=Auto renew cert
Wants=network-online.target
After=network-online.target

[Service]
EnvironmentFile=/path/to/.env
# 使用动态用户账号来增强安全性
DynamicUser=yes
ExecStart=/bin/bash -c 'ACCOUNT_FILE="${CREDENTIALS_DIRECTORY}/account.json" /path/to/auto-cert'
LoadCredential=account.json:/path/to/acme-account.json # 应该在设置服务前运行程序来自动生成 acme 账号文件
Type=simple

[Install]
WantedBy=multi-user.target
```

然后，在 `/etc/systemd/system/` 目录下创建名为 `aliyun-auto-cert.timer` 的定时器文件：

```ini
[Unit]
Description=Daily auto-cert

[Timer]
# 在启动的 10 分钟后/每日自动更新证书
OnBootSec=10m
OnUnitActiveSec=1d
Persistent=true

[Install]
WantedBy=timers.target
```

最后，启用并立即启动定时器/服务：

```bash
systemctl daemon-reload
systemctl enable --now aliyun-auto-cert.timer
```
