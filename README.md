# Pape SDK Server

> 当前适配游戏版本：6.0.0（3705）

《恋与深空》（叠纸游戏 / Papegames）专用 SDK / 登录后端的自建服务端实现，附带原版用户中心。使用 Go 编写，提供 SDK 接口、账号登录、用户中心、公告与热更新、以及游戏 TCP 网关等能力，可搭配 SQLite 或 MySQL 使用。

> 本实现针对《恋与深空》的 SDK 协议与常量，并非叠纸游戏通用后端。

## 功能特性

- **SDK 服务**：客户端初始化、服务器列表、参数下发、隐私协议、敏感词、热更新补丁列表等接口。
- **账号登录**：手机短信注册 / 登录、密码登录、Token 刷新、实名信息、风控 SecureToken 等 passport 接口，请求 / 响应遵循 BFF 加密。
- **用户中心**：内置《恋与深空》原版用户中心网页端（`static/usercenter`），支持注册、找回密码、修改密码、换绑手机号、注销账号。
- **短信**：支持虚拟验证码（开发调试）与阿里云短信真实下发两种模式。
- **配置回源**：配置 JSON 存在时本地响应，文件或参数缺失时按客户端原始请求透明回源官服。
- **本地代理**：内置 HTTP/HTTPS MITM 正向代理，所有 `papegames.com` 请求直接进入本进程路由，不依赖 SDK、登录或用户中心的监听端口。
- **游戏网关**：独立 TCP 端口用于游戏连接（目前为占位 stub，尚未实现真实游戏协议）。

## 目录结构

```
cmd/pape-server/      程序入口
internal/
  app/                路由、接口处理、启动逻辑
  config/             配置加载
  crypto/             BFF / AES 加解密
  data/               JSONC 配置文件读取
  httpx/              HTTP 相关封装
  sms/                短信下发（阿里云）
  store/              数据存储（SQLite / MySQL）
static/
  contracts/          协议页面
  notices/            公告页面
  usercenter/         用户中心前端
config/               服务器列表、公告、热更新补丁等 JSON 配置
data/                 SQLite 数据库及自动生成的代理叶证书
config.example.yaml   配置模板
```

## 快速开始

### 环境要求

- Go 1.23+

### 构建

```bash
go build -o pape-server ./cmd/pape-server
```

### 配置

复制配置模板并按需修改：

```bash
cp config.example.yaml config.yaml
```

### 运行

```bash
./pape-server -config config.yaml
```

默认从当前目录的 `config.yaml` 读取配置，可用 `-config` 指定路径。

健康检查：`GET /healthz`。

### 内置代理

代理服务可以单独启用；即使 `sdk`、`login`、`usercenter` 都设置为 `enabled: false`，所有
`papegames.com` 及其子域名的 HTTP/HTTPS 请求仍会直接进入完整的内部业务路由。其他域名
一律返回 `403 Forbidden`，不会连接上游。

```yaml
proxy:
  enabled: true
  bindhost: "0.0.0.0"
  bindport: 8888
  usehttp2: true
  collect_route: true
  caprivkey: "./certs/rootca.key"
  cacert: "./certs/rootca.crt"
```

首次启用代理时，服务会用指定 CA 生成 `data/pape.pem` 和 `data/pape.key`；后续启动会复用
仍然有效且由当前 CA 签发的证书。客户端必须信任该 CA。代理会记录 CONNECT 去向、内部或
上游路由、HTTP 状态、响应大小、协议版本和耗时。

`collect_route: true` 时，代理遇到本服务尚未实现的 Papegames 路由会透明回源，并在
`collected_route/<时间_方法_域名_路径>/` 中保存 `request.json`、`request.body`、
`response.json` 和 `response.body`。这些文件可能包含 Token、Cookie 等敏感信息。

若客户端在 CONNECT 中使用 IP 地址，代理不会连接该 IP，而是先进行本地 TLS 握手，再通过
TLS SNI 和解密后的 HTTP Host 验证 Papegames 身份。非 Papegames SNI/Host 仍会被拒绝。

## 配置说明

配置采用 YAML 格式，主要字段如下（完整示例见 [config.example.yaml](config.example.yaml)）：

| 配置项 | 说明 |
| --- | --- |
| `db_uri` | 数据库连接串，支持 `sqlite://` 与 `mysql://` |
| `config_dir` | JSON 配置文件目录 |
| `sdk` / `login` / `usercenter` / `game` | 各服务的开关、监听地址、端口及对外访问地址 |
| `proxy` | HTTP/HTTPS 正向代理；支持 HTTP/2，并使用指定 CA 对 Papegames 域名做本地 MITM |
| `authentication.realpassword` | 为 `true` 时 `/v1/user/login` 校验密码 |
| `authentication.realsms` | 为 `true` 时仅接受真实生成的验证码，不接受固定虚拟码 |
| `authentication.smsregister` | 为 `true` 时短信仅用于注册新账号，老账号需先设置 / 找回密码后密码登录 |
| `constants` / `usercenter_constants` | 客户端 ID、AppKey、AES Key 等常量 |
| `realname_identity` | 实名信息 |
| `hosts` | 各官方域名 |
| `sms` | 短信服务商配置（当前支持阿里云） |

配置接口数据位于 `config/`，包括 `sdkclient.json`、`payment_init.json`、`parameter.json`、
`sensitive_client_version.json`、`sensitive_client.json`、`announcelist.json`、
`patchlist.json` 等。JSON/JSONC 文件不存在时会回源；
`parameter.json` 中缺少客户端请求的 key 时也会回源。

### 认证模式

- **虚拟短信（默认）**：`realsms: false`，可用固定虚拟验证码，便于本地开发调试。
- **真实短信**：`realsms: true` 并填写阿里云 `access_key_id`、`access_key_secret`、`sign_name`、`template_code` 等。
- **密码登录**：`realpassword: true` 后 `/v1/user/login` 会校验密码，密码可通过重置流程或用户中心设置。

## 主要接口

### SDK / Passport

- `GET  /contract`、`GET /notice/:name`
- `POST /v1/user/account/send/code`、`POST /v1/user/exists/send/code`
- `POST /v1/user/mobile/register`、`POST /v1/user/login`
- `POST /v1/user/login/token/refresh`、`/v1/user/password/reset`
- `GET  /v1/gameconfig/serverlist`、`/entries`、`/privacyagreement`、`/patchlist`、`/parameter`
- `GET  /v1/conf/sdkclient`
- `POST /v1/payment/init`
- `GET  /ws`（WebSocket）

### 用户中心（网页）

- `GET  /usercenter`
- `POST /usercenter/register`、`recover-password`、`change-password`、`delete-account`、`change-phone`

### 游戏网关

独立 TCP 端口（默认 `13001`）接受游戏连接。**目前为占位 stub**，仅接受连接、尚未实现真实游戏协议。

## 数据存储

- **SQLite**（默认）：`db_uri: "sqlite://./data/data.db"`，开箱即用。
- **MySQL**：`db_uri: "mysql://user:pass@tcp(host:port)/db?charset=utf8mb4&parseTime=true&loc=Local"`。

## 说明

本项目仅供学习与研究使用。
