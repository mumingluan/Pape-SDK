package app

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"

	bffcrypto "pape-sdk/internal/crypto"
	"pape-sdk/internal/data"
	"pape-sdk/internal/httpx"
	"pape-sdk/internal/store"
)

func (a *App) form(c *gin.Context) (map[string]string, int64, error) {
	if err := c.Request.ParseForm(); err != nil {
		return nil, 0, err
	}
	out := map[string]string{}
	for k, vals := range c.Request.Form {
		if len(vals) > 0 {
			out[k] = vals[0]
		}
	}
	needsSign := strings.HasPrefix(c.Request.URL.Path, "/v1/user/") || out["data"] != "" || out["timestamp"] != ""
	if needsSign && out["sign"] == "" && out["sig"] == "" {
		return nil, 0, errors.New("缺少签名")
	}
	bff := a.bffFor(out)
	if out["sign"] != "" && !strings.EqualFold(out["sign"], bff.Sign(out)) {
		return nil, 0, errors.New("签名错误")
	}
	c.Set("passport_bff", bff)
	ts, _ := strconv.ParseInt(out["timestamp"], 10, 64)
	if out["data"] != "" && ts != 0 {
		inner, err := bff.DecryptData(out["data"], ts)
		if err != nil {
			return nil, ts, err
		}
		for k, v := range inner {
			out[k] = v
		}
	}
	return out, ts, nil
}

func (a *App) bffFor(out map[string]string) bffcrypto.BFF {
	if out["app_id"] == a.userCenterBFF.AppID || out["clientid"] == a.userCenterClientID {
		return a.userCenterBFF
	}
	return a.bff
}

func (a *App) passportBFF(c *gin.Context) bffcrypto.BFF {
	if v, ok := c.Get("passport_bff"); ok {
		if bff, ok := v.(bffcrypto.BFF); ok {
			return bff
		}
	}
	return a.bff
}

func phoneOf(form map[string]string) string {
	for _, k := range []string{"phone", "mobile", "account", "bind_account", "change_account", "new_phone"} {
		if strings.TrimSpace(form[k]) != "" {
			return strings.TrimSpace(form[k])
		}
	}
	return ""
}

func (a *App) phoneForSMS(form map[string]string) (string, error) {
	if phone := phoneOf(form); phone != "" {
		return phone, nil
	}
	u, err := a.userFromFields(form)
	if err == nil && u.Phone != "" {
		return u.Phone, nil
	}
	if form["nid"] != "" || form["token"] != "" || form["access_token"] != "" || form["long_token"] != "" || form["longToken"] != "" {
		return "", err
	}
	return "", nil
}

var chinaMobilePattern = regexp.MustCompile(`^1[3-9][0-9]{9}$`)

func normalizeChinaPhone(phone string) (string, error) {
	phone = strings.TrimSpace(phone)
	if !chinaMobilePattern.MatchString(phone) {
		return "", errors.New("请输入正确的中国大陆手机号")
	}
	return phone, nil
}

func (a *App) issueSMS(phone string) (string, error) {
	return a.issueSMSForScene(phone, "default", "")
}

func (a *App) issueSMSForScene(phone, scene, ip string) (string, error) {
	phone, err := normalizeChinaPhone(phone)
	if err != nil {
		return "", err
	}
	if scene == "" {
		return "", errors.New("缺少验证码用途")
	}
	if ip == "" {
		ip = "unknown"
	}
	if a.cfg.Auth.RealSMS {
		if err := a.store.CheckSMSRate(phone, ip); err != nil {
			return "", err
		}
	}
	code := phone[len(phone)-6:]
	if a.cfg.Auth.RealSMS {
		code = randomDigits(6)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.sms.SendCode(ctx, phone, code, scene); err != nil {
			return "", err
		}
	}
	return code, a.store.IssueSMS(phone, scene, code, ip)
}

func (a *App) verifySMS(phone, code string) error {
	return a.verifySMSForScene(phone, "default", code)
}

func (a *App) verifySMSForScene(phone, scene, code string) error {
	phone, err := normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	if scene == "" {
		return errors.New("缺少验证码用途")
	}
	if !a.cfg.Auth.RealSMS && code == phone[len(phone)-6:] {
		return nil
	}
	return a.store.VerifySMS(phone, scene, code)
}

func (a *App) mirrorSMSCode(phone, code, ip string, scenes ...string) {
	seen := map[string]bool{}
	for _, scene := range scenes {
		if scene == "" || seen[scene] {
			continue
		}
		seen[scene] = true
		if err := a.store.MirrorSMS(phone, scene, code, ip); err != nil {
			log.Printf("[sms] mirror scene=%s phone=%s failed: %v", scene, phone, err)
		}
	}
}

func (a *App) checkSMSForAnyScene(phone, code string, scenes ...string) error {
	var last error
	for _, scene := range uniqueScenes(scenes...) {
		if err := a.store.CheckSMS(phone, scene, code); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last != nil {
		return last
	}
	return errors.New("请先获取验证码")
}

func (a *App) verifySMSForAnyScene(phone, code string, scenes ...string) error {
	var last error
	for _, scene := range uniqueScenes(scenes...) {
		if err := a.verifySMSForScene(phone, scene, code); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last != nil {
		return last
	}
	return errors.New("请先获取验证码")
}

func uniqueScenes(scenes ...string) []string {
	out := make([]string, 0, len(scenes))
	seen := map[string]bool{}
	for _, scene := range scenes {
		if scene == "" || seen[scene] {
			continue
		}
		seen[scene] = true
		out = append(out, scene)
	}
	return out
}

func (a *App) setPassword(userID int64, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return a.store.SetPasswordHash(userID, string(hash))
}

func validatePassword(password string) error {
	if len(password) < 6 {
		return errors.New("密码至少需要 6 位")
	}
	return nil
}

func (a *App) passwordLogin(phone, password string) (store.User, error) {
	phone, err := normalizeChinaPhone(phone)
	if err != nil {
		return store.User{}, err
	}
	if password == "" {
		return store.User{}, errors.New("请输入密码")
	}
	u, ok, err := a.store.UserByPhone(phone)
	if err != nil {
		return store.User{}, err
	}
	if !ok {
		return store.User{}, errors.New("未查询到账号信息")
	}
	if !u.PasswordHash.Valid || u.PasswordHash.String == "" {
		return store.User{}, errors.New("账号未设置密码，请先找回或设置密码")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte(password)); err != nil {
		return store.User{}, errors.New("密码错误")
	}
	token, err := a.store.TouchLogin(u.ID)
	if err != nil {
		return store.User{}, err
	}
	u.Token = token
	if refreshed, ok, err := a.store.UserByPhone(phone); err == nil && ok {
		u.RefreshToken = refreshed.RefreshToken
	}
	return u, nil
}

func (a *App) userFromFields(fields map[string]string) (store.User, error) {
	token := fields["token"]
	if token == "" {
		token = fields["access_token"]
	}
	if token != "" {
		u, ok, err := a.store.UserByToken(token)
		if err != nil {
			return store.User{}, err
		}
		if !ok {
			return store.User{}, errors.New("登录凭证无效")
		}
		return u, nil
	}
	longToken := fields["long_token"]
	if longToken == "" {
		longToken = fields["longToken"]
	}
	if longToken != "" {
		u, ok, err := a.store.UserByLongToken(longToken)
		if err != nil {
			return store.User{}, err
		}
		if !ok {
			return store.User{}, errors.New("长连接凭证无效")
		}
		return u, nil
	}
	return store.User{}, errors.New("缺少登录凭证")
}

func (a *App) jsonOrForm(c *gin.Context) (map[string]string, error) {
	ct := c.GetHeader("Content-Type")
	if strings.Contains(ct, "application/json") {
		var obj map[string]any
		if err := c.ShouldBindJSON(&obj); err != nil {
			return nil, err
		}
		out := map[string]string{}
		for k, v := range obj {
			out[k] = fmt.Sprint(v)
		}
		return out, nil
	}
	out, _, err := a.form(c)
	return out, err
}

func (a *App) encrypted(c *gin.Context, payload any, timestamp int64) {
	data, err := a.passportBFF(c).PassportData(payload, timestamp)
	if err != nil {
		passportError(c, err)
		return
	}
	c.JSON(200, httpx.Envelope(data))
}

func passportError(c *gin.Context, err error) {
	info := "请求失败"
	if err != nil && err.Error() != "" {
		info = err.Error()
	}
	code := 1
	if strings.Contains(info, "account not found") || strings.Contains(info, "no logged-in user") || strings.Contains(info, "未查询到账号信息") {
		code = 1020
		info = "未查询到账号信息"
	}
	c.JSON(200, httpx.ErrorEnvelope(code, info))
}

func (a *App) commonInit(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"oss_no_md5_channels": []string{"2", "3", "BattleLog", "Photos", "Common", "MiaoCardLog", "CriticalLog", "SDKLog", "LocalData", "PSTemplateData", "LocalDataRecord", "CrossGameData"}}))
}

func (a *App) riskSecureToken(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"token": "local_" + randomHex(16), "expire": time.Now().Add(10 * time.Minute).Unix()}))
}

func (a *App) sendCode(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	scene := form["scene"]
	if scene == "" {
		scene = "account"
	}
	phone, err := a.phoneForSMS(form)
	if err != nil {
		passportError(c, err)
		return
	}
	code, err := a.issueSMSForScene(phone, scene, c.ClientIP())
	if err != nil {
		passportError(c, err)
		return
	}
	if a.cfg.Auth.RealSMS {
		log.Printf("[sms] real code generated for %s: %s", phone, code)
	}
	a.mirrorSMSCode(phone, code, c.ClientIP(), scene, "account", "login", "register", "bind", "change_phone", "usercenter")
	c.JSON(200, httpx.Envelope(nil))
}

func (a *App) sendCodeWithData(c *gin.Context) {
	form, ts, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	scene := form["scene"]
	if scene == "" {
		scene = "password"
	}
	phone, err := a.phoneForSMS(form)
	if err != nil {
		passportError(c, err)
		return
	}
	code, err := a.issueSMSForScene(phone, scene, c.ClientIP())
	if err != nil {
		passportError(c, err)
		return
	}
	if a.cfg.Auth.RealSMS {
		log.Printf("[sms] real code generated for %s: %s", phone, code)
	}
	a.mirrorSMSCode(phone, code, c.ClientIP(), scene, "account", "login", "register", "password", "bind", "change_phone", "usercenter")
	a.encrypted(c, gin.H{}, ts)
}

func (a *App) accountExists(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	phone, err := normalizeChinaPhone(phoneOf(form))
	if err != nil {
		passportError(c, err)
		return
	}
	_, ok, err := a.store.UserByPhone(phone)
	if err != nil {
		passportError(c, err)
		return
	}
	c.JSON(200, httpx.Envelope(gin.H{"exists": ok, "account_exists": ok}))
}

func (a *App) accountCodeVerify(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	phone := phoneOf(form)
	if phone == "" {
		c.JSON(200, httpx.Envelope(gin.H{"verify_token": "local_" + randomHex(12)}))
		return
	}
	scene := form["scene"]
	if scene == "" {
		scene = "account"
	}
	if err := a.checkSMSForAnyScene(phone, form["code"], scene, "account", "login", "register", "password"); err != nil {
		passportError(c, err)
		return
	}
	c.JSON(200, httpx.Envelope(gin.H{"verify_token": "local_" + randomHex(12)}))
}

func (a *App) passwordReset(c *gin.Context) {
	form, ts, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	phone := phoneOf(form)
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		passportError(c, err)
		return
	}
	if phone == "" {
		passportError(c, errors.New("请输入手机号"))
		return
	}
	scene := form["scene"]
	if scene == "" {
		scene = "password"
	}
	if err := a.verifySMSForScene(phone, scene, form["code"]); err != nil {
		passportError(c, err)
		return
	}
	u, ok, err := a.store.UserByPhone(phone)
	if err != nil {
		passportError(c, err)
		return
	}
	if !ok {
		if a.cfg.Auth.RealPassword || a.cfg.Auth.SMSRegister {
			passportError(c, errors.New("未查询到账号信息"))
			return
		}
		u, _, err = a.store.GetOrCreateUser(phone)
		if err != nil {
			passportError(c, err)
			return
		}
	}
	if a.cfg.Auth.RealPassword {
		if form["password"] == "" {
			passportError(c, errors.New("请输入密码"))
			return
		}
		if err := a.setPassword(u.ID, form["password"]); err != nil {
			passportError(c, err)
			return
		}
	}
	a.encrypted(c, gin.H{}, ts)
}

func (a *App) mobileRegister(c *gin.Context) { a.loginLike(c, 0) }
func (a *App) userLogin(c *gin.Context)      { a.loginLike(c, 0) }

func (a *App) loginLike(c *gin.Context, isNew int) {
	form, ts, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	phone := phoneOf(form)
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		passportError(c, err)
		return
	}
	if a.cfg.Auth.RealPassword && form["password"] != "" {
		u, err := a.passwordLogin(phone, form["password"])
		if err != nil {
			passportError(c, err)
			return
		}
		a.encrypted(c, a.loginPayload(u, "", 0), ts)
		return
	}
	if a.cfg.Auth.SMSRegister {
		scene := form["scene"]
		if scene == "" {
			scene = "login"
		}
		if err := a.verifySMSForAnyScene(phone, form["code"], scene, "login", "account", "register", "usercenter"); err != nil {
			passportError(c, err)
			return
		}
		if _, ok, err := a.store.UserByPhone(phone); err != nil || ok {
			if err != nil {
				passportError(c, err)
				return
			}
			passportError(c, errors.New("该账号已注册，请先设置或找回密码后使用密码登录"))
			return
		}
	}
	u, _, err := a.store.GetOrCreateUser(phone)
	if err != nil {
		passportError(c, err)
		return
	}
	if a.cfg.Auth.RealPassword && form["password"] != "" {
		if err := a.setPassword(u.ID, form["password"]); err != nil {
			passportError(c, err)
			return
		}
	}
	a.encrypted(c, a.loginPayload(u, "", isNew), ts)
}

func (a *App) refreshToken(c *gin.Context) {
	form, ts, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	refresh := form["refresh_token"]
	if refresh == "" {
		refresh = form["refreshToken"]
	}
	u, token, err := a.store.RefreshByToken(refresh)
	if err != nil {
		passportError(c, err)
		return
	}
	a.encrypted(c, a.loginPayload(u, token, 0), ts)
}

func (a *App) profileGet(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	u, err := a.userFromFields(form)
	if err != nil {
		passportError(c, err)
		return
	}
	c.JSON(200, httpx.Envelope(a.profileResponsePayload(u)))
}

func (a *App) phoneBindInfo(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	u, err := a.userFromFields(form)
	if err != nil {
		passportError(c, err)
		return
	}
	bound := u.Phone != ""
	c.JSON(200, httpx.Envelope(gin.H{
		"phone":              u.Phone,
		"mobile":             u.Phone,
		"account":            u.Phone,
		"bind":               bound,
		"is_bind":            bound,
		"bind_status":        map[bool]int{false: 0, true: 1}[bound],
		"status":             map[bool]int{false: 0, true: 1}[bound],
		"phoneleftseconds":   0,
		"emailleftseconds":   0,
		"third_bind_infos":   []any{},
		"third_account_type": -1,
	}))
}

func (a *App) accountBindPhone(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	newPhone, err := normalizeChinaPhone(phoneOf(form))
	if err != nil {
		passportError(c, err)
		return
	}
	code := strings.TrimSpace(form["code"])
	if code == "" {
		passportError(c, errors.New("请输入验证码"))
		return
	}
	if err := a.verifySMSForAnyScene(newPhone, code, form["scene"], "bind", "account", "change_phone", "usercenter", "default", "login", "register", "password"); err != nil {
		passportError(c, err)
		return
	}
	u, err := a.userFromFields(form)
	if err != nil {
		u, err = a.store.LatestUser()
		if err != nil {
			passportError(c, err)
			return
		}
	}
	if err := a.store.UpdatePhone(u.ID, newPhone); err != nil {
		passportError(c, err)
		return
	}
	c.JSON(200, httpx.Envelope(gin.H{
		"status":           0,
		"valid":            true,
		"phone":            newPhone,
		"mobile":           newPhone,
		"phoneleftseconds": 0,
	}))
}

func (a *App) cometAcquire(c *gin.Context) {
	form, ts, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	u, err := a.userFromFields(form)
	if err != nil {
		passportError(c, err)
		return
	}
	_, token, err := a.store.CreateCometSession(u.ID)
	if err != nil {
		passportError(c, err)
		return
	}
	channels := []string{
		fmt.Sprintf("sdk#%d:%d/rw", a.cfg.Constants.ClientID, u.NID),
		fmt.Sprintf("sdk#%d:all/rw", a.cfg.Constants.ClientID),
		fmt.Sprintf("acem#%d:%d/rw", a.cfg.Constants.ClientID, u.NID),
	}
	a.encrypted(c, gin.H{"recepit": token, "channels": channels}, ts)
}

func (a *App) realGet(c *gin.Context) {
	_, ts, _ := a.form(c)
	a.encrypted(c, a.realInfoPayload(true), ts)
}

func (a *App) realAdd(c *gin.Context) { c.JSON(200, httpx.Envelope(nil)) }

func (a *App) emptyStatus(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"status": 0, "valid": true}))
}

func (a *App) emptyList(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"list": []any{}, "roles": []any{}, "rolelist": []any{}, "items": []any{}}))
}

func (a *App) mailLinkOK(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"sent": true, "link": ""}))
}

func (a *App) ossAcquire(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"host": "", "dir": "", "accessid": "", "policy": "", "signature": ""}))
}

func (a *App) faceVerifyStub(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"return_url": "", "receipt": "local_" + randomHex(12)}))
}

func (a *App) qrcodeGenerate(c *gin.Context) {
	id := "local_" + randomHex(8)
	c.JSON(200, httpx.Envelope(gin.H{"qrcode_id": id, "code": id, "url": ""}))
}

func (a *App) qrcodeStatus(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"status": 0, "scanned": false, "confirmed": false}))
}

func (a *App) shortURLLink(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"short_url": "", "url": ""}))
}

func (a *App) shortURLQuery(c *gin.Context) {
	c.JSON(200, httpx.Envelope(gin.H{"url": ""}))
}

func (a *App) loginCheck(c *gin.Context) {
	_, ts, _ := a.form(c)
	a.encrypted(c, gin.H{"youth_msg": a.verifiedYouth(false, false)}, ts)
}

func (a *App) youthReport(c *gin.Context) {
	_, ts, _ := a.form(c)
	a.encrypted(c, gin.H{"youth_msg": a.verifiedYouth(true, true)}, ts)
}

func (a *App) serverList(c *gin.Context) {
	a.dataJSON(c, "serverlist.json", true)
}

func (a *App) entries(c *gin.Context) {
	name := "entries_cmp.json"
	if strings.Contains(c.Request.URL.RawQuery, "Announce") {
		name = "announce.json"
	}
	a.dataJSON(c, name, false)
}

func (a *App) privacyAgreement(c *gin.Context) {
	a.dataJSON(c, "privacyagreement.json", false)
}

func (a *App) patchList(c *gin.Context) {
	a.dataJSON(c, "patchlist.json", true)
}

func (a *App) dataJSON(c *gin.Context, name string, includeMsg bool) {
	obj, err := data.LoadJSONC(a.cfg.ConfigPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			a.forwardUpstream(c, a.apiUpstreamAuthority(), a.shouldCollect(c), "missing_config:"+name, true)
			return
		}
		c.JSON(500, gin.H{"error": err.Error(), "file": name})
		return
	}
	officialTextJSON(c, httpx.WithGenerated(obj, includeMsg))
}

func (a *App) sdkClient(c *gin.Context) {
	obj, err := data.LoadJSONC(a.cfg.ConfigPath("sdkclient.json"))
	if err != nil {
		if os.IsNotExist(err) {
			a.forwardUpstream(c, a.apiUpstreamAuthority(), a.shouldCollect(c), "missing_config:sdkclient.json", true)
			return
		}
		c.JSON(500, gin.H{"error": err.Error(), "file": "sdkclient.json"})
		return
	}
	if version := c.Query("sdkversion"); version != "" {
		obj["sdkversion"] = version
	}
	c.JSON(200, httpx.WithGenerated(obj, true))
}

func (a *App) parameter(c *gin.Context) {
	key := c.Query("key")
	obj, err := data.LoadJSONC(a.cfg.ConfigPath("parameter.json"))
	if err != nil {
		if os.IsNotExist(err) {
			a.forwardUpstream(c, a.apiUpstreamAuthority(), a.shouldCollect(c), "missing_config:parameter.json", true)
			return
		}
		c.JSON(500, gin.H{"error": err.Error(), "file": "parameter.json"})
		return
	}
	value, exists := obj[key]
	if !exists {
		a.forwardUpstream(c, a.apiUpstreamAuthority(), a.shouldCollect(c), "missing_parameter:"+key, true)
		return
	}
	officialTextJSON(c, gin.H{"gameConfigParameter": gin.H{"key": key, "value": value}, "ret": 0, "time": time.Now().Unix()})
}

func (a *App) sensitiveClientVersion(c *gin.Context) {
	obj, err := data.LoadJSONC(a.cfg.ConfigPath("sensitive_client_version.json"))
	if err != nil {
		if os.IsNotExist(err) {
			a.forwardUpstream(c, a.apiUpstreamAuthority(), a.shouldCollect(c), "missing_config:sensitive_client_version.json", true)
			return
		}
		c.JSON(500, gin.H{"error": err.Error(), "file": "sensitive_client_version.json"})
		return
	}
	officialTextJSON(c, httpx.WithGenerated(obj, false))
}

func (a *App) sensitiveClient(c *gin.Context) {
	a.dataJSON(c, "sensitive_client.json", false)
}

func (a *App) announceList(c *gin.Context) {
	a.dataJSON(c, "announcelist.json", true)
}

func (a *App) paymentInit(c *gin.Context) {
	obj, err := data.LoadJSONC(a.cfg.ConfigPath("payment_init.json"))
	if err != nil {
		if os.IsNotExist(err) {
			a.forwardUpstream(c, a.cfg.Hosts.Passport, a.shouldCollect(c), "missing_config:payment_init.json", true)
			return
		}
		c.JSON(500, gin.H{"error": err.Error(), "file": "payment_init.json"})
		return
	}
	obj["request_id"] = uuid.NewString()
	c.JSON(200, obj)
}

func (a *App) throttle(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	u, err := a.userFromFields(form)
	if err != nil {
		passportError(c, err)
		return
	}
	receipt := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("receipt:%d:%d", u.NID, time.Now().Unix())))
	c.JSON(200, gin.H{"code": 0, "info": "OK", "request_id": uuid.NewString()[:10], "data": gin.H{"status": 3, "rate": 5000, "receipt": receipt, "queue_sequence": 0, "queue_wait_seconds": 0, "max_delay_seconds": 60}})
}

func (a *App) contract(c *gin.Context) {
	key := c.DefaultQuery("key", "default")
	names := map[string]string{
		"default":        "default.html",
		"accountUser":    "account_user.html",
		"accountPrivacy": "account_privacy.html",
		"sensitive":      "sensitive.html",
	}
	name := names[key]
	if name == "" {
		name = names["default"]
	}
	a.staticHTML(c, filepath.Join("static", "contracts", name))
}

func (a *App) notice(c *gin.Context) {
	names := map[string]string{
		"service":      "service.html",
		"privacy":      "privacy.html",
		"childPrivacy": "child_privacy.html",
		"sdkList":      "sdk_list.html",
	}
	name := names[c.Param("name")]
	if name == "" {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	a.staticHTML(c, filepath.Join("static", "notices", name))
}

func (a *App) staticHTML(c *gin.Context, rel string) {
	raw, err := os.ReadFile(a.cfg.Resolve(rel))
	if err != nil {
		c.String(404, "missing static file: %s", rel)
		return
	}
	c.Data(200, "text/html; charset=utf-8", raw)
}

func (a *App) userCenterHome(c *gin.Context) {
	if a.serveUserCenterFile(c, "index.html") {
		return
	}
	c.String(404, "missing static file: %s", filepath.Join("static", "usercenter", "index.html"))
}

func (a *App) userCenterAsset(c *gin.Context) {
	rel := strings.TrimPrefix(c.Param("filepath"), "/")
	if rel == "" {
		rel = "index.html"
	}
	if strings.HasPrefix(rel, "api/") {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	clean := filepath.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		c.JSON(400, gin.H{"error": "bad_path"})
		return
	}
	if !a.serveUserCenterFile(c, clean) {
		a.serveUserCenterFile(c, "index.html")
	}
}

func (a *App) shouldServeUserCenterSPA(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		return false
	}
	p := c.Request.URL.Path
	if strings.HasPrefix(p, "/v1/") ||
		strings.HasPrefix(p, "/rpc/") ||
		strings.HasPrefix(p, "/ws") ||
		strings.HasPrefix(p, "/healthz") ||
		strings.HasPrefix(p, "/favicon.ico") {
		return false
	}
	if ext := filepath.Ext(p); ext != "" {
		return false
	}
	accept := c.GetHeader("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func (a *App) serveUserCenterFile(c *gin.Context, rel string) bool {
	root := a.cfg.Resolve(filepath.Join("static", "usercenter"))
	target := filepath.Join(root, rel)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	if absTarget != absRoot && !strings.HasPrefix(absTarget, absRoot+string(os.PathSeparator)) {
		return false
	}
	info, err := os.Stat(absTarget)
	if err != nil || info.IsDir() {
		return false
	}
	if rel == "index.html" {
		raw, err := os.ReadFile(absTarget)
		if err != nil {
			return false
		}
		token := randomHex(24)
		c.SetCookie("uc_csrf", token, 3600, "/usercenter", "", false, true)
		html := strings.ReplaceAll(string(raw), "{{csrf}}", token)
		c.Data(200, "text/html; charset=utf-8", []byte(html))
		return true
	}
	http.ServeFile(c.Writer, c.Request, absTarget)
	return true
}

func (a *App) userCenterSendCode(c *gin.Context) {
	if !a.validUserCenterCSRF(c) {
		a.userCenterResult(c, errors.New("页面已过期，请刷新后重试"))
		return
	}
	phone, err := normalizeChinaPhone(c.PostForm("phone"))
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	scene := c.DefaultPostForm("scene", "usercenter")
	code, err := a.issueSMSForScene(phone, scene, c.ClientIP())
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if a.cfg.Auth.RealSMS {
		log.Printf("[sms] real code generated for %s: %s", phone, code)
	}
	a.userCenterResult(c, nil)
}

func (a *App) userCenterRegister(c *gin.Context) {
	if !a.validUserCenterCSRF(c) {
		a.userCenterResult(c, errors.New("页面已过期，请刷新后重试"))
		return
	}
	phone, code, password := c.PostForm("phone"), c.PostForm("code"), c.PostForm("password")
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if err := a.verifySMSForScene(phone, "register", code); err != nil {
		a.userCenterResult(c, err)
		return
	}
	u, err := a.store.CreateUser(phone)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if password != "" {
		err = a.setPassword(u.ID, password)
	}
	a.userCenterResult(c, err)
}

func (a *App) userCenterRecoverPassword(c *gin.Context) {
	if !a.validUserCenterCSRF(c) {
		a.userCenterResult(c, errors.New("页面已过期，请刷新后重试"))
		return
	}
	phone, code, password := c.PostForm("phone"), c.PostForm("code"), c.PostForm("password")
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if password == "" {
		a.userCenterResult(c, errors.New("请输入密码"))
		return
	}
	if err := a.verifySMSForScene(phone, "password", code); err != nil {
		a.userCenterResult(c, err)
		return
	}
	u, ok, err := a.store.UserByPhone(phone)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if !ok {
		a.userCenterResult(c, errors.New("未查询到账号信息"))
		return
	}
	a.userCenterResult(c, a.setPassword(u.ID, password))
}

func (a *App) userCenterChangePassword(c *gin.Context) {
	if !a.validUserCenterCSRF(c) {
		a.userCenterResult(c, errors.New("页面已过期，请刷新后重试"))
		return
	}
	phone, oldPassword, newPassword := c.PostForm("phone"), c.PostForm("old_password"), c.PostForm("new_password")
	u, err := a.passwordLogin(phone, oldPassword)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if newPassword == "" {
		a.userCenterResult(c, errors.New("请输入新密码"))
		return
	}
	a.userCenterResult(c, a.setPassword(u.ID, newPassword))
}

func (a *App) userCenterDeleteAccount(c *gin.Context) {
	if !a.validUserCenterCSRF(c) {
		a.userCenterResult(c, errors.New("页面已过期，请刷新后重试"))
		return
	}
	phone, password := c.PostForm("phone"), c.PostForm("password")
	u, err := a.passwordLogin(phone, password)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	a.userCenterResult(c, a.store.DeleteUser(u.ID))
}

func (a *App) userCenterChangePhone(c *gin.Context) {
	if !a.validUserCenterCSRF(c) {
		a.userCenterResult(c, errors.New("页面已过期，请刷新后重试"))
		return
	}
	oldPhone, newPhone, password, code := c.PostForm("old_phone"), c.PostForm("new_phone"), c.PostForm("password"), c.PostForm("code")
	var err error
	oldPhone, err = normalizeChinaPhone(oldPhone)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	newPhone, err = normalizeChinaPhone(newPhone)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	u, err := a.passwordLogin(oldPhone, password)
	if err != nil {
		a.userCenterResult(c, err)
		return
	}
	if err := a.verifySMSForScene(newPhone, "change_phone", code); err != nil {
		a.userCenterResult(c, err)
		return
	}
	a.userCenterResult(c, a.store.UpdatePhone(u.ID, newPhone))
}

func (a *App) userCenterResult(c *gin.Context, err error) {
	if strings.Contains(c.GetHeader("Accept"), "application/json") || strings.EqualFold(c.GetHeader("X-Requested-With"), "XMLHttpRequest") {
		if err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
		return
	}
	if err != nil {
		c.Data(400, "text/html; charset=utf-8", []byte("<!doctype html><meta charset=\"utf-8\"><p>失败："+htmlEscape(err.Error())+"</p><p><a href=\"/usercenter\">返回用户中心</a></p>"))
		return
	}
	c.Data(200, "text/html; charset=utf-8", []byte("<!doctype html><meta charset=\"utf-8\"><p>操作成功</p><p><a href=\"/usercenter\">返回用户中心</a></p>"))
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(s)
}

func (a *App) validUserCenterCSRF(c *gin.Context) bool {
	cookie, err := c.Cookie("uc_csrf")
	if err != nil || cookie == "" {
		return false
	}
	return hmacEqual(cookie, c.PostForm("csrf"))
}

func hmacEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (a *App) websocket(c *gin.Context) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := up.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	send := func(requestID string) error {
		if requestID == "" {
			requestID = uuid.NewString()
		}
		msg, _ := json.Marshal(gin.H{"command": "heartbeat", "version": "1", "request_id": requestID, "code": 0, "info": "OK"})
		return conn.WriteMessage(websocket.BinaryMessage, msg)
	}
	_ = send("")
	for {
		mt, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.CloseMessage {
			return
		}
		var obj map[string]any
		requestID := ""
		if json.Unmarshal(payload, &obj) == nil {
			if v, ok := obj["request_id"].(string); ok {
				requestID = v
			}
		}
		_ = send(requestID)
	}
}

func (a *App) loginPayload(u store.User, token string, isNew int) gin.H {
	if token == "" {
		token = u.Token
	}
	refresh := ""
	if u.RefreshToken.Valid {
		refresh = u.RefreshToken.String
	}
	return gin.H{"nid": u.NID, "openid": u.OpenID, "isnew": isNew, "isguest": 0, "refresh_token": refresh, "token": token, "accounttype": 1, "real_switch": true, "youth_switch": true, "youth_report_interval": 300, "youth_msg": a.verifiedYouth(true, true), "roleid": 0, "location": gin.H{"continent_code": "AS", "continent_name": "Asia", "country_iso_code": "CN", "country_name": "China", "province_code": "", "province_name": ""}}
}

func (a *App) profilePayload(u store.User) gin.H {
	return gin.H{
		"nid":              u.NID,
		"phone":            u.Phone,
		"mobile":           u.Phone,
		"account":          u.Phone,
		"email":            "",
		"birthday":         "",
		"avatar":           "",
		"nickname":         "",
		"accounttype":      1,
		"is_guest":         0,
		"has_password":     u.PasswordHash.Valid && u.PasswordHash.String != "",
		"phoneleftseconds": 0,
		"emailleftseconds": 0,
		"hasrealinfo":      1,
		"real_switch":      true,
		"youth_switch":     true,
		"youth_msg":        a.verifiedYouth(true, true),
		"realname":         a.cfg.RealNameIdentity.RealName,
		"realid":           a.cfg.RealNameIdentity.RealID,
		"authstatus":       3,
		"third_bind_infos": []any{},
	}
}

func (a *App) profileResponsePayload(u store.User) gin.H {
	profile := a.profilePayload(u)
	out := gin.H{
		"profile":   profile,
		"addresses": []any{},
	}
	for k, v := range profile {
		out[k] = v
	}
	return out
}

func (a *App) realInfoPayload(includeName bool) gin.H {
	youth := a.verifiedYouth(includeName, true)
	return gin.H{
		"authstatus":  3,
		"hasrealinfo": 1,
		"real_switch": true,
		"realname":    youth["realname"],
		"realid":      youth["realid"],
		"youth_msg":   youth,
	}
}

func (a *App) verifiedYouth(includeName bool, adult bool) gin.H {
	out := gin.H{"authstatus": 3, "limit": 0, "loginban": 0, "loginbanbeg": "", "loginbanend": "", "onlinetoday": 0, "age": 19, "is_guest": 0, "hasrealinfo": 1, "limitType": 0, "is_holiday": 0, "remaintoday": 9999999, "limit_age": 18, "adult": adult}
	if includeName {
		out["realid"] = a.cfg.RealNameIdentity.RealID
		out["realname"] = a.cfg.RealNameIdentity.RealName
	}
	return out
}

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := cryptorand.Read(raw); err != nil {
		var s strings.Builder
		for s.Len() < n*2 {
			s.WriteString(strings.ReplaceAll(uuid.NewString(), "-", ""))
		}
		return s.String()[:n*2]
	}
	return hex.EncodeToString(raw)
}

func randomDigits(n int) string {
	raw := make([]byte, n)
	if _, err := cryptorand.Read(raw); err != nil {
		return "123456"
	}
	var b strings.Builder
	for _, v := range raw {
		b.WriteByte(byte('0' + int(v)%10))
	}
	return b.String()
}
