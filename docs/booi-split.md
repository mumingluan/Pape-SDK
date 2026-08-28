# Pape-BOOI 服务拆分

游戏协议、`/rpc/nuanlogin`、角色与游戏票据已迁往同级 `Pape-BOOI` 项目。本 SDK 只保留账号、Passport、用户中心、配置下发与代理。

SDK 对外登录响应会包含 `openid`。Pape-BOOI 使用 SDK 的
`POST /inner/v1/accounts/verify-login` 校验 `openid + SDK token`；SDK 的角色列表接口则使用 BOOI 的
`POST /inner/v1/players/roles/query`。

`booi_inner` 以 serverlist 中的服务器 `id` 为键。SDK 会并发查询所有配置项，角色信息仍以
BOOI 数据中的 `zone_id` 组织，同时在每个角色对象中补充 `ServerID`。

SDK 不注册 `/rpc/nuanlogin`，也不监听 13001。`config/serverlist.json` 中的 `login_url` 和 `addr` 必须指向 Pape-BOOI 的公共监听器。
