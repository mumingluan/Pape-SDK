package app

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (a *App) innerRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "pape-sdk-inner", "time": time.Now().Unix()})
	})
	inner := router.Group("/inner/v1", a.innerAuth())
	inner.POST("/accounts/verify-login", a.verifyInnerLogin)
	return router
}

func (a *App) innerAuth() gin.HandlerFunc {
	want := []byte("Bearer " + a.cfg.Inner.AuthToken)
	return func(c *gin.Context) {
		got := []byte(c.GetHeader("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func (a *App) verifyInnerLogin(c *gin.Context) {
	var request struct {
		OpenID string `json:"openid"`
		Token  string `json:"token"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": err.Error()})
		return
	}
	byOpenID, ok, err := a.store.UserByOpenID(request.OpenID)
	if err != nil || !ok {
		log.Printf("[sdk-inner] verify-login rejected reason=openid_not_found openid=%q token_fp=%s", request.OpenID, tokenFingerprint(request.Token))
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "OpenID 或登录凭证无效"})
		return
	}
	byToken, ok, err := a.store.UserByToken(request.Token)
	if err != nil || !ok {
		log.Printf("[sdk-inner] verify-login rejected reason=token_not_found openid=%q token_fp=%s", request.OpenID, tokenFingerprint(request.Token))
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "OpenID 或登录凭证无效"})
		return
	}
	if byToken.ID != byOpenID.ID {
		log.Printf("[sdk-inner] verify-login rejected reason=identity_mismatch openid=%q openid_user=%d token_user=%d token_fp=%s", request.OpenID, byOpenID.ID, byToken.ID, tokenFingerprint(request.Token))
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "OpenID 或登录凭证无效"})
		return
	}
	status, _, err := a.store.Cancellation(byOpenID.ID)
	if err != nil {
		log.Printf("[sdk-inner] verify-login rejected reason=cancellation_status_error openid=%q: %v", request.OpenID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"valid": false, "error": "账号状态查询失败"})
		return
	}
	if status == cancellationStatusCoolingOff {
		log.Printf("[sdk-inner] verify-login rejected reason=cancellation_cooling_off openid=%q", request.OpenID)
		c.JSON(http.StatusLocked, gin.H{"valid": false, "error": "账号处于注销冷静期（账号锁定期）"})
		return
	}
	if strings.TrimSpace(request.OpenID) != byOpenID.OpenID {
		log.Printf("[sdk-inner] verify-login accepted legacy_openid=%q canonical_openid=%q user=%d", request.OpenID, byOpenID.OpenID, byOpenID.ID)
	}
	c.JSON(http.StatusOK, gin.H{"valid": true, "openid": byOpenID.OpenID, "nid": byOpenID.NID})
}

func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:4])
}
