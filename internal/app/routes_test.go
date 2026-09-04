package app

import (
	"testing"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/config"
)

func TestRoleRoutesAreMountedOnceOnEachPublicAPISurface(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	for name, router := range map[string]*gin.Engine{
		"sdk":        a.publicRouter(true, false),
		"usercenter": a.publicRouter(false, true),
	} {
		routes := routeMethods(router)
		for _, path := range []string{
			"/v1/user/roleinfo/get",
			"/v1/user/role/list",
			"/v1/user/gamerolelist",
			"/v1/user/transfer/role/list",
		} {
			if !routes[path]["GET"] || !routes[path]["POST"] {
				t.Errorf("%s missing role route %s: %#v", name, path, routes[path])
			}
		}
		if _, exists := routes["/rpc/nuanlogin"]; exists {
			t.Errorf("%s unexpectedly mounts /rpc/nuanlogin", name)
		}
	}
}

func TestListenerRouteComposition(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	sdkRoutes := routeMethods(a.publicRouter(true, false))
	userCenterRoutes := routeMethods(a.publicRouter(false, true))
	if !sdkRoutes["/v1/gameconfig/serverlist"]["GET"] {
		t.Fatal("SDK listener is missing gameconfig serverlist")
	}
	for _, path := range []string{"/v1/gameconfig/ratingguidenodelist", "/v1/ip/locate", "/v1/user/checkrealinfo", "/v1/user/getsafestatus", "/v1/user/unfinishedorder"} {
		if !sdkRoutes[path]["GET"] {
			t.Errorf("SDK listener is missing %s", path)
		}
	}
	if !sdkRoutes["/v1/inform/add"]["POST"] {
		t.Fatal("SDK listener is missing /v1/inform/add")
	}
	if _, exists := userCenterRoutes["/v1/gameconfig/serverlist"]; exists {
		t.Fatal("user-center listener unexpectedly exposes SDK gameconfig routes")
	}
	if !userCenterRoutes["/usercenter"]["GET"] {
		t.Fatal("user-center listener is missing HTML entry")
	}
	if _, exists := sdkRoutes["/usercenter"]; exists {
		t.Fatal("SDK-only listener unexpectedly exposes user-center HTML")
	}
}

func routeMethods(router *gin.Engine) map[string]map[string]bool {
	result := map[string]map[string]bool{}
	for _, route := range router.Routes() {
		if result[route.Path] == nil {
			result[route.Path] = map[string]bool{}
		}
		result[route.Path][route.Method] = true
	}
	return result
}
