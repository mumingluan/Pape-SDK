# Pape SDK Server

《恋与深空》（叠纸游戏 / Papegames）专用 SDK / 登录后端的自建服务端实现，附带原版用户中心。使用 Go 编写，提供 SDK 接口、账号登录、用户中心、公告与热更新、以及游戏 TCP 网关等能力，可搭配 SQLite 或 MySQL 使用。

> 本实现针对《恋与深空》的 SDK 协议与常量，并非叠纸游戏通用后端。

## 功能特性

- **SDK 服务**：客户端初始化、服务器列表、参数下发、隐私协议、敏感词、热更新补丁列表等接口。
- **账号登录**：手机短信注册 / 登录、密码登录、Token 刷新、实名信息、风控 SecureToken 等 passport 接口，请求 / 响应遵循 BFF 加密。
- **用户中心**：内置《恋与深空》原版用户中心网页端（`static/usercenter`），支持注册、找回密码、修改密码、换绑手机号、注销账号。
- **短信**：支持虚拟验证码（开发调试）与阿里云短信真实下发两种模式。
- **热更新**：`patchlist` 可由本地 `data/patchlist.json` 直接提供，或反向代理官方 CDN。
- **游戏网关**：独立 TCP 端口用于游戏连接（目前为占位 stub，尚未实现真实游戏协议）。

## 目录结构

```
cmd/pape-server/      程序入口
internal/
  app/                路由、接口处理、启动逻辑
  config/             配置加载
  crypto/             BFF / AES 加解密
  data/               内置数据文件读取
  httpx/              HTTP 相关封装
  sms/                短信下发（阿里云）
  store/              数据存储（SQLite / MySQL）
static/
  contracts/          协议页面
  notices/            公告页面
  usercenter/         用户中心前端
data/                 服务器列表、公告、热更新补丁等 JSON 数据
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

## 配置说明

配置采用 YAML 格式，主要字段如下（完整示例见 [config.example.yaml](config.example.yaml)）：

| 配置项 | 说明 |
| --- | --- |
| `db_uri` | 数据库连接串，支持 `sqlite://` 与 `mysql://` |
| `data_dir` | 数据文件目录 |
| `sdk` / `login` / `usercenter` / `game` | 各服务的开关、监听地址、端口及对外访问地址 |
| `authentication.realpassword` | 为 `true` 时 `/v1/user/login` 校验密码 |
| `authentication.realsms` | 为 `true` 时仅接受真实生成的验证码，不接受固定虚拟码 |
| `authentication.smsregister` | 为 `true` 时短信仅用于注册新账号，老账号需先设置 / 找回密码后密码登录 |
| `constants` / `usercenter_constants` | 客户端 ID、AppKey、AES Key 等常量 |
| `realname_identity` | 实名信息 |
| `hosts` | 各官方域名 |
| `parameters` | 下发给客户端的参数 |
| `hotfix.proxy` | `false` 时补丁列表来自本地 `data/patchlist.json`；`true` 时反代 `proxy_url` |
| `sms` | 短信服务商配置（当前支持阿里云） |

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
- `GET  /ws`（WebSocket）

### 用户中心（网页）

- `GET  /usercenter`
- `POST /usercenter/register`、`recover-password`、`change-password`、`delete-account`、`change-phone`

### 游戏网关

独立 TCP 端口（默认 `13001`）接受游戏连接。**目前为占位 stub**，仅接受连接、尚未实现真实游戏协议。

## 数据存储

- **SQLite**（默认）：`db_uri: "sqlite://./data.db"`，开箱即用。
- **MySQL**：`db_uri: "mysql://user:pass@tcp(host:port)/db?charset=utf8mb4&parseTime=true&loc=Local"`。

## 说明

本项目仅供学习与研究使用。