package app

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/booi"
	"pape-sdk/internal/config"
	bffcrypto "pape-sdk/internal/crypto"
	"pape-sdk/internal/httpx"
	"pape-sdk/internal/sms"
	"pape-sdk/internal/store"
)

type App struct {
	cfg                *config.Config
	store              *store.Store
	booi               *booi.Pool
	bff                bffcrypto.BFF
	userCenterBFF      bffcrypto.BFF
	userCenterClientID string
	sms                sms.Provider
}

func Run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.Inner.Enabled && strings.TrimSpace(cfg.Inner.AuthToken) == "" {
		return errors.New("inner.auth_token is required when inner is enabled")
	}
	dataStore, err := store.Open(cfg.DBURI, cfg.BaseDir)
	if err != nil {
		return err
	}
	smsProvider, err := sms.New(cfg.SMS)
	if err != nil {
		return err
	}
	app := &App{
		cfg: cfg, store: dataStore, sms: smsProvider, booi: booi.NewPool(cfg.BOOIInner),
		bff:                bffcrypto.BFF{AppID: cfg.Constants.AppID, AppKey: cfg.Constants.AppKey, AESKey: cfg.Constants.AESKey},
		userCenterBFF:      bffcrypto.BFF{AppID: cfg.UserCenterConstants.AppID, AppKey: cfg.UserCenterConstants.AppKey, AESKey: cfg.UserCenterConstants.AESKey},
		userCenterClientID: strconv.Itoa(cfg.UserCenterConstants.ClientID),
	}

	var proxyHandler http.Handler
	if cfg.Proxy.Enabled {
		proxyHandler, err = newProxyHandler(cfg, app.publicRouter(true, true))
		if err != nil {
			return err
		}
	}
	type group struct {
		host, name      string
		port            int
		sdk, userCenter bool
	}
	groups := map[string]*group{}
	add := func(name string, service config.Service, apply func(*group)) {
		if !service.Enabled {
			return
		}
		key := net.JoinHostPort(service.BindHost, strconv.Itoa(service.BindPort))
		item := groups[key]
		if item == nil {
			item = &group{host: service.BindHost, port: service.BindPort, name: name}
			groups[key] = item
		}
		apply(item)
	}
	add("sdk", cfg.Sdk, func(item *group) { item.sdk = true })
	add("usercenter", cfg.UserCenter.Service, func(item *group) { item.userCenter = true })

	started := 0
	for _, item := range groups {
		started++
		go serveHTTP(item.name, item.host, item.port, app.publicRouter(item.sdk, item.userCenter))
	}
	if cfg.Inner.Enabled {
		started++
		go serveHTTP("inner", cfg.Inner.BindHost, cfg.Inner.BindPort, app.innerRouter())
	}
	if cfg.Proxy.Enabled {
		started++
		go serveHTTP("proxy", cfg.Proxy.BindHost, cfg.Proxy.BindPort, proxyHandler)
	}
	if started == 0 {
		return errors.New("no service enabled")
	}
	select {}
}

func serveHTTP(name, host string, port int, handler http.Handler) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	log.Printf("%s HTTP listening on http://%s", name, address)
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("%s HTTP failed: %v", name, err)
	}
}

func (a *App) publicRouter(withSDK, withUserCenter bool) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), a.requestLog())
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "pape-sdk", "time": time.Now().Unix()})
	})
	if withSDK {
		router.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "not found") })
	} else if withUserCenter {
		router.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/usercenter") })
	}
	if withSDK {
		a.mountSDK(router)
	}
	if withUserCenter && !withSDK {
		a.mountUserCenterAPIs(router)
	}
	if withUserCenter {
		a.mountUserCenter(router)
	}
	router.NoRoute(func(c *gin.Context) {
		if a.cfg.Proxy.CollectRoute && isProxyInternalRequest(c.Request) {
			a.forwardUpstream(c, "", true, "unimplemented_route", false)
			return
		}
		if strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
			a.websocket(c)
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/v1/user/") {
			c.JSON(http.StatusOK, httpx.ErrorEnvelope(404, "接口不存在"))
			return
		}
		if withUserCenter && a.shouldServeUserCenterSPA(c) && a.serveUserCenterFile(c, "index.html") {
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "path": c.Request.URL.Path})
	})
	return router
}

func (a *App) requestLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if a.store != nil {
			a.store.LogRequest(c.Request.Method, c.Request.Host, c.Request.URL.Path, c.Request.ContentLength)
		}
	}
}
