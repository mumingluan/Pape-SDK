package app

import (
	"time"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/httpx"
)

// mountSDK composes the public SDK listener from domain-specific route groups.
// Each concrete path is registered in exactly one helper below.
func (a *App) mountSDK(router *gin.Engine) {
	router.GET("/favicon.ico", func(c *gin.Context) { c.Status(204) })
	router.GET("/ws", a.websocket)
	a.mountPublicDocumentRoutes(router)
	a.mountPassportRoutes(router)
	a.mountAccessoryRoutes(router)
	a.mountReportRoutes(router)
	a.mountGameConfigRoutes(router)
	a.mountSharedStubRoutes(router)
	a.mountSDKOnlyStubRoutes(router)
}

func (a *App) mountReportRoutes(router *gin.Engine) {
	router.POST("/v1/inform/add", a.addUserReport)
}

// mountUserCenterAPIs intentionally reuses the same Passport route groups as
// the SDK listener. The user-center HTML routes are mounted separately.
func (a *App) mountUserCenterAPIs(router *gin.Engine) {
	a.mountPublicDocumentRoutes(router)
	a.mountPassportRoutes(router)
	a.mountAccessoryRoutes(router)
	a.mountSharedStubRoutes(router)
}

func (a *App) mountPublicDocumentRoutes(router *gin.Engine) {
	router.GET("/contract", a.contract)
	router.GET("/notice/:name", a.notice)
}

func (a *App) mountPassportRoutes(router *gin.Engine) {
	a.mountAuthenticationRoutes(router)
	a.mountCancellationRoutes(router)
	a.mountRoleRoutes(router)
	a.mountAccountCompatibilityRoutes(router)
}

func (a *App) mountAuthenticationRoutes(router *gin.Engine) {
	router.Any("/v1/user/common/init", a.commonInit)
	router.Any("/v1/user/risk/securetoken/acquire", a.riskSecureToken)
	router.POST("/v1/user/account/send/code", a.sendCode)
	router.POST("/v1/user/exists/send/code", a.sendCodeWithData)
	router.Any("/v1/user/account/exists", a.accountExists)
	router.Any("/v1/user/account/code/verify", a.accountCodeVerify)
	router.Any("/v1/user/password/reset", a.passwordReset)
	router.POST("/v1/user/mobile/register", a.mobileRegister)
	router.POST("/v1/user/login", a.userLogin)
	router.Any("/v1/user/login/token/refresh", a.refreshToken)
	router.Any("/v1/user/profile/get", a.profileGet)
	router.Any("/v1/user/comet/acquire", a.cometAcquire)
	router.Any("/v1/user/real/get", a.realGet)
	router.Any("/v1/user/real/add", a.realAdd)
	router.Any("/v1/user/login/check", a.loginCheck)
	router.GET("/v1/user/checkrealinfo", a.checkRealInfo)
	router.GET("/v1/user/getsafestatus", a.getSafeStatus)
	router.GET("/v1/user/unfinishedorder", a.unfinishedOrder)
	router.Any("/v1/user/youth/report/online", a.youthReport)
	router.POST("/v1/user/oss/authorization", a.storageAuthorization)
}

func (a *App) mountCancellationRoutes(router *gin.Engine) {
	router.Any("/v1/user/cancellation/status", a.cancellationStatus)
	router.Any("/v1/user/cancellation/handle", a.cancellationHandle)
	router.Any("/v1/user/cancellation/role/list", a.cancellationRoleList)
	router.Any("/v1/user/cancellation/role/check", a.cancellationCheck)
	router.Any("/v1/user/cancellation/submit", a.cancellationCheck)
	router.Any("/v1/user/cancellation/role/status", a.cancellationCheck)
	router.Any("/v1/user/cancellation/code/verify", a.cancellationCodeVerify)
	router.Any("/v1/user/cancellation/real/check", a.cancellationRealCheck)
	router.Any("/v1/user/cancellation/password/check", a.cancellationPasswordCheck)
}

// roleinfo/get is the client-facing server-selection response. The remaining
// paths are compatibility aliases that share the list-shaped response.
func (a *App) mountRoleRoutes(router *gin.Engine) {
	router.Any("/v1/user/roleinfo/get", a.roleInfo)
	anyRoutes(router, a.roleList,
		"/v1/user/role/list",
		"/v1/user/gamerolelist",
		"/v1/user/transfer/role/list",
	)
	router.Any("/v1/user/rolestatus", a.emptyStatus)
}

func (a *App) mountAccountCompatibilityRoutes(router *gin.Engine) {
	router.Any("/v1/user/account/send/link", a.mailLinkOK)
	router.Any("/v1/user/password/reset/link", a.emptyStatus)
	router.Any("/v1/user/account/send/code/nid", a.sendCodeWithData)
	router.Any("/v1/user/account/code/nid/verify", a.accountCodeVerify)
	router.Any("/v1/user/account/send/link/nid", a.mailLinkOK)
	router.Any("/v1/user/password/reset/nid", a.passwordReset)
	router.Any("/v1/user/address/set/batch", a.emptyStatus)
	router.Any("/v1/user/account/send/code/nid/bind", a.sendCodeWithData)
	anyRoutes(router, a.accountBindPhone, "/v1/user/account/bind", "/v1/user/account/change")
	anyRoutes(router, a.emptyStatus,
		"/v1/user/account/link/change/verify",
		"/v1/user/account/link/verify",
		"/v1/user/login/redirect",
		"/v1/user/transfer/zone/limit",
		"/v1/user/transfer/eligible",
		"/v1/user/transfer/real/check",
		"/v1/user/transfer/submit",
		"/v1/user/transfer/query",
		"/v1/user/subscribe/remind",
		"/v1/user/subscribe",
		"/v1/user/3rd/bind/email",
		"/v1/user/birthday/set",
		"/v1/user/appeal/check",
		"/v1/user/appeal/submit",
		"/v1/user/oauth/login",
		"/v1/user/oauth/mobile/login",
		"/v1/user/oauth/auth",
		"/v1/user/account/3rd/bind/phone",
	)
	router.Any("/v1/user/account/send/link/change", a.mailLinkOK)
	router.Any("/v1/user/account/send/code/bind", a.sendCodeWithData)
	router.Any("/v1/user/transfer/zone/get", a.emptyList)
	router.Any("/v1/user/transfer/real/add", a.realAdd)
	router.Any("/v1/user/transfer/list", a.emptyList)
	router.Any("/v1/user/subscribe/link", a.mailLinkOK)
	router.Any("/v1/user/subscription/list", a.emptyList)
	router.Any("/v1/user/oss/acquire", a.ossAcquire)
	router.Any("/v1/user/risk/face/h5/code", a.faceVerifyStub)
	router.Any("/v1/user/qrcode/generate", a.qrcodeGenerate)
	router.Any("/v1/user/qrcode/status", a.qrcodeStatus)
	router.Any("/v1/user/account/3rd/bindinfo", a.phoneBindInfo)
}

func (a *App) mountAccessoryRoutes(router *gin.Engine) {
	router.Any("/v1/accessories/shorturl/link", a.shortURLLink)
	router.Any("/v1/accessories/shorturl/query", a.shortURLQuery)
	anyRoutes(router, a.serverList,
		"/v1/accessories/gameconfig/gosserverlist",
		"/v1/accessories/gameconfig/serverlist",
	)
	router.Any("/v1/accessories/risk/face/result", a.emptyStatus)
	router.Any("/v1/accessories/risk/face/qrcode/generate", a.qrcodeGenerate)
	router.Any("/v1/accessories/risk/face/qrcode/status", a.qrcodeStatus)
	router.Any("/v1/accessories/risk/face/qrcode/scan", a.emptyStatus)
}

func (a *App) mountGameConfigRoutes(router *gin.Engine) {
	router.GET("/v1/gameconfig/serverlist", a.serverList)
	router.GET("/v1/gameconfig/entries", a.entries)
	router.GET("/v1/gameconfig/privacyagreement", a.privacyAgreement)
	router.GET("/v1/gameconfig/patchlist", a.patchList)
	router.GET("/v1/gameconfig/ratingguidenodelist", a.ratingGuideNodeList)
	router.GET("/v1/ip/locate", a.ipLocate)
	router.GET("/v1/conf/sdkclient", a.sdkClient)
	router.POST("/v1/payment/init", a.paymentInit)
	router.GET("/v1/gameconfig/parameter", a.parameter)
	router.Any("/v1/throttle/acquire", a.throttle)
	router.GET("/v1/gameconfig/sensitive/client/version", a.sensitiveClientVersion)
	router.GET("/v1/gameconfig/sensitive/client", a.sensitiveClient)
	router.GET("/v1/announcelist", a.announceList)
}

func (a *App) mountSharedStubRoutes(router *gin.Engine) {
	router.Any("/v1/log/sendtlog", func(c *gin.Context) { c.JSON(200, gin.H{"ret": 0, "time": time.Now().Unix()}) })
	router.Any("/v1/risk/biz/init", func(c *gin.Context) { c.JSON(200, httpx.Envelope(nil)) })
	anyRoutes(router, a.emptyStatus,
		"/v1/risk/captcha/g/check",
		"/v1/risk/phone/check",
		"/v1/risk/code/check",
	)
}

func (a *App) mountSDKOnlyStubRoutes(router *gin.Engine) {
	router.Any("/rqd/pb/async", func(c *gin.Context) { c.JSON(200, httpx.Envelope(nil)) })
	router.Any("/v3/cloudconf", func(c *gin.Context) { c.JSON(200, httpx.Envelope(nil)) })
	router.Any("/deviceprofile/v4", func(c *gin.Context) { c.JSON(200, httpx.Envelope(nil)) })
}

func (a *App) mountUserCenter(router *gin.Engine) {
	router.GET("/usercenter", a.userCenterHome)
	router.GET("/usercenter/*filepath", a.userCenterAsset)
	router.POST("/usercenter/send-code", a.userCenterSendCode)
	router.POST("/usercenter/register", a.userCenterRegister)
	router.POST("/usercenter/recover-password", a.userCenterRecoverPassword)
	router.POST("/usercenter/change-password", a.userCenterChangePassword)
	router.POST("/usercenter/delete-account", a.userCenterDeleteAccount)
	router.POST("/usercenter/change-phone", a.userCenterChangePhone)
}

func anyRoutes(router *gin.Engine, handler gin.HandlerFunc, paths ...string) {
	for _, path := range paths {
		router.Any(path, handler)
	}
}
