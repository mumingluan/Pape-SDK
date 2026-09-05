# 国际服配置差异核对

核对资料：`R:/os-init.har`、`R:/os-login.har`，以及五个应用的本地配置。HAR 请求域名取 Host 头，路径和查询取 URL；POST 表单也参与选择。比较仅去除顶层 time/request_id，保留实际业务时间、开关和内容。样本索引与规范化 SHA-256 见 international-config-evidence.json。

| 配置 | 四外服比较结果 | 运行时选择 |
|---|---|---|
| patchlist | 4 份；商店包名、渠道、地区、CDN、scene_version、记录 ID 不同 | AppID，或 game clientid + channel/region |
| sdkclient | 4 份；config.netDiagnosis2、netDiagnosis3、payMsg 不同 | AppID 或 SDK clientid |
| accessories_init | 4 份；data.config 下同样三项不同 | AppID |
| payment_init | 5 次响应归一化后相同，四服均有样本 | 每 AppID 保留独立文件，方便之后覆盖 |
| privacyagreement | 4 份；协议标题、正文、链接、版本和 area_id 不同 | clientid=1067 + areaid；2=繁中、3=英文、4=日文、5=韩文 |
| entries | CMP_Popup 在四服相同；英文另有 America_Age_Policy_Parameter（空数组）、Announce_Tab | 解析 GET/POST 的 codes；兼容双重 URL 编码、多个 code |
| parameter | 四服的 PreDownload_Switch、ResUpdate_CheckResIntegrity 相同；英文额外抓到 5 个 key | clientid + key；保留 7 项，不逐响应覆盖 |
| serverlist | 当前四份为本服自托管路由，调整 clientid/region/channel；不是四份官方响应 | 每 AppID 独立文件，保留 BOOI 登录和 Gate 地址 |
| announcelist | EN 登录 HAR 有 1 份公告列表；其余三服缺样本，不能认定四服一致 | 游戏客户端目录；不据此推断四服相同 |
| announce | 国服保留原配置；国际 Announce_Tab 内容来自 entries 样本 | 国际使用 entries.json 中 Announce_Tab |
| sensitive_client / sensitive_client_version | 无外服样本 | 缺文件转发对应上游，不使用国服配置 |
| ratingguidenodelist | 无外服样本 | 缺文件转发对应上游，不使用国服配置 |

国服原 JSON 全量迁移到 config/apps/kmT84W9D。原配置含自托管服务器和人工调整，不能当作本次同时间官方国服采样；不将其与外服不同简单等同于官方地区差异。兼容无选择参数的旧请求保留 config/common。已选定应用或 game client 的请求只读取其作用域，缺文件不会回退至国服 common。

目录：config/apps/{kmT84W9D,DsEb1STz,QEiTBAMf,Ivfk6q0x,vIin01GU}；国际共享配置 config/game-clients/1067。隐私协议使用 privacyagreement_area_<areaid>.json；entries.json 为 code 到条目数组的映射；parameter.json 为 key 到 value 的映射。未知 key/code 保留对应上游回退行为。

四外服的生产 AppID/加密配置从各 APKS 内 base.apk 的 assets/u8_developer_config.properties 的 BFF_CONFIG3 提取。EN 登录 HAR 的 10 个签名及加密响应验证通过。密钥仅存本机 config.yaml，不包含在比较报告里。

邮箱注册、密码登录、绑定/解绑使用共同的本地 SDK 账号库，因此五个应用共享本地账号 ID；这不意味着所有官方第三方账号互通。邮箱 OTP 当前 outbox 模式，仅在本机落地，实际邮件投递需配置 SMTP。
