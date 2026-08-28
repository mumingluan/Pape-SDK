# HTTP 路由架构

`publicRouter` 只负责按监听器用途组合路由，不直接维护成百上千个路径：

```text
SDK listener
  ├─ PublicDocumentRoutes
  ├─ PassportRoutes
  │   ├─ AuthenticationRoutes
  │   ├─ CancellationRoutes
  │   ├─ RoleRoutes
  │   └─ AccountCompatibilityRoutes
  ├─ AccessoryRoutes
  ├─ GameConfigRoutes
  ├─ SharedStubRoutes
  └─ SDKOnlyStubRoutes

UserCenter API listener
  ├─ PublicDocumentRoutes
  ├─ PassportRoutes
  ├─ AccessoryRoutes
  ├─ SharedStubRoutes
  └─ UserCenter HTML routes
```

同一个具体路径只在一个领域注册函数中声明。SDK 与 UserCenter 通过组合复用注册函数，避免复制路由清单。

## 角色路由

- `/v1/user/roleinfo/get`：客户端区服选择页面使用的主路由，返回以 ZoneID 组织的 `roleinfo`。
- `/v1/user/role/list`：通用列表兼容路由。
- `/v1/user/gamerolelist`：旧命名兼容路由。
- `/v1/user/transfer/role/list`：转服流程兼容路由。
- `/v1/user/cancellation/role/list`：注销流程，目前保持独立空列表语义。

前三个列表形态的路径共享 `roleList` Handler，但主 `roleinfo/get` 保持官方响应结构，不与列表接口混用。
