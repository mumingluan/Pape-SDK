package app

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/httpx"
)

func (a *App) ratingGuideNodeList(c *gin.Context) {
	a.dataJSON(c, "ratingguidenodelist.json", true)
}

func (a *App) checkRealInfo(c *gin.Context) {
	form, _, ok := a.cancellationUser(c)
	if !ok {
		return
	}
	matched := strings.TrimSpace(form["realname"]) == a.cfg.RealNameIdentity.RealName &&
		strings.TrimSpace(form["realid"]) == a.cfg.RealNameIdentity.RealID
	officialTextJSON(c, httpx.WithGenerated(map[string]any{
		"authstatus": 3, "realinfostatus": matched,
	}, true))
}

func (a *App) getSafeStatus(c *gin.Context) {
	_, user, ok := a.cancellationUser(c)
	if !ok {
		return
	}
	safe, err := a.store.UserSafeStatus(user.ID)
	if err != nil {
		passportError(c, err)
		return
	}
	status := 1
	if safe {
		status = 0
	}
	officialTextJSON(c, gin.H{"ret": 0, "safestatus": status, "time": time.Now().Unix()})
}

func (a *App) unfinishedOrder(c *gin.Context) {
	officialTextJSON(c, gin.H{"ret": 0, "time": time.Now().Unix(), "unfinished": false})
}

type geoLocation struct {
	ContinentCode string `json:"continent_code"`
	ContinentName string `json:"continent_name"`
	CountryCode   string `json:"country_iso_code"`
	CountryName   string `json:"country_name"`
	ProvinceCode  string `json:"province_code"`
	ProvinceName  string `json:"province_name"`
	IsEU          bool   `json:"is_in_european_union"`
}

type cachedGeoLocation struct {
	location geoLocation
	expires  time.Time
}

var geoCache = struct {
	sync.Mutex
	entries map[string]cachedGeoLocation
}{entries: make(map[string]cachedGeoLocation)}

func (a *App) ipLocate(c *gin.Context) {
	location := locateIP(c.ClientIP())
	officialTextJSON(c, gin.H{"location": location, "ret": 0, "time": time.Now().Unix()})
}

func locateIP(address string) geoLocation {
	fallback := geoLocation{
		ContinentCode: "AS", ContinentName: "亚洲", CountryCode: "CN", CountryName: "中国",
		ProvinceCode: "", ProvinceName: "", IsEU: false,
	}
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return fallback
	}
	key := ip.String()
	geoCache.Lock()
	if cached, ok := geoCache.entries[key]; ok && time.Now().Before(cached.expires) {
		geoCache.Unlock()
		return cached.location
	}
	geoCache.Unlock()

	type response struct {
		Success       bool   `json:"success"`
		Continent     string `json:"continent"`
		ContinentCode string `json:"continent_code"`
		Country       string `json:"country"`
		CountryCode   string `json:"country_code"`
		Region        string `json:"region"`
		RegionCode    string `json:"region_code"`
		IsEU          bool   `json:"is_eu"`
	}
	endpoint := "https://ipwho.is/" + url.PathEscape(key) + "?fields=success,continent,continent_code,country,country_code,region,region_code,is_eu"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fallback
	}
	request.Header.Set("User-Agent", "pape-sdk/geoip")
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	res, err := client.Do(request)
	if err != nil {
		return fallback
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fallback
	}
	var result response
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&result); err != nil || !result.Success || result.CountryCode == "" {
		return fallback
	}
	location := geoLocation{
		ContinentCode: result.ContinentCode, ContinentName: result.Continent,
		CountryCode: result.CountryCode, CountryName: result.Country,
		ProvinceCode: result.RegionCode, ProvinceName: result.Region, IsEU: result.IsEU,
	}
	if location.ContinentCode == "AS" && location.ContinentName == "Asia" {
		location.ContinentName = "亚洲"
	}
	if location.CountryCode == "CN" && location.CountryName == "China" {
		location.CountryName = "中国"
	}
	geoCache.Lock()
	geoCache.entries[key] = cachedGeoLocation{location: location, expires: time.Now().Add(6 * time.Hour)}
	geoCache.Unlock()
	return location
}
