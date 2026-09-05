package app

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"pape-sdk/internal/config"
	"pape-sdk/internal/data"
	"pape-sdk/internal/httpx"
	"pape-sdk/internal/store"
)

func (a *App) requestApplication(c *gin.Context) (config.Application, bool) {
	_ = c.Request.ParseForm()
	return a.cfg.Application(c.Request.Form.Get("app_id"), firstNonEmpty(c.Request.Form.Get("clientid"), c.Request.Form.Get("client_id")), c.Request.Form.Get("region"), firstNonEmpty(c.Request.Form.Get("channel"), c.Request.Form.Get("sdk_channel")))
}
func (a *App) requestConfigPath(c *gin.Context, name string) string {
	app, selected := a.requestApplication(c)
	clientID := firstNonEmpty(c.Request.Form.Get("clientid"), c.Request.Form.Get("client_id"))
	var scopedPath string
	if selected {
		scopedPath = a.cfg.ApplicationConfigPath(app, name)
		if _, err := os.Stat(scopedPath); err == nil || !os.IsNotExist(err) {
			return scopedPath
		}
		clientID = app.GameClientID
	}
	if dir := a.cfg.GameConfigDirs[clientID]; dir != "" {
		path := a.cfg.Resolve(filepath.Join(dir, name))
		// A game-client scope is authoritative, including missing resources.
		return path
	}
	if selected && app.ConfigDir != "" {
		return scopedPath
	}
	// Unrecognized applications must never receive another application's config.
	if id := c.Request.Form.Get("app_id"); id != "" {
		return a.cfg.Resolve("config/unconfigured-application/" + filepath.Base(name))
	}
	return a.cfg.ConfigPath(name)
}
func (a *App) requestAPI(c *gin.Context) string {
	if app, ok := a.requestApplication(c); ok && app.API != "" {
		return app.API
	}
	if strings.HasSuffix(authorityHostname(c.Request.Host), ".infoldgames.com") {
		return "api.infoldgames.com:443"
	}
	return a.apiUpstreamAuthority()
}
func (a *App) requestClientID(c *gin.Context) int {
	if app, ok := a.requestApplication(c); ok {
		return app.ClientID
	}
	return a.cfg.Constants.ClientID
}
func (a *App) emailRegister(c *gin.Context) {
	// loginLike validates the signature, verification code, uniqueness and registration policy.
	a.loginLike(c, 1)
}
func (a *App) accessoriesInit(c *gin.Context) {
	obj, err := data.LoadJSONC(a.requestConfigPath(c, "accessories_init.json"))
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(200, httpx.Envelope(gin.H{}))
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	obj["request_id"] = uuid.NewString()
	c.JSON(200, obj)
}
func (a *App) accountUnbind(c *gin.Context) {
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
	phone, email := a.store.AccountBindings(u)
	var retained string
	switch form["kind"] {
	case "phone":
		retained = email
	case "email":
		retained = phone
	default:
		passportError(c, errors.New("请选择手机号或邮箱"))
		return
	}
	if retained == "" {
		passportError(c, errors.New("手机号和邮箱至少保留一个"))
		return
	}
	if err = a.verifySMSForAnyScene(retained, form["code"], "unbind"); err != nil {
		passportError(c, err)
		return
	}
	err = a.store.UnbindVerified(u.ID, form["kind"], retained)
	if err != nil {
		passportError(c, err)
		return
	}
	c.JSON(200, httpx.Envelope(gin.H{"status": 0}))
}
func (a *App) sendEmailCode(address, code, scene string) error {
	cfg := a.cfg.Email
	if cfg.Mode == "outbox" {
		dir := cfg.OutboxDir
		if dir == "" {
			dir = "data/email-outbox"
		}
		dir = a.cfg.Resolve(dir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(gin.H{"to": address, "code": code, "scene": scene, "created_at": time.Now().UTC(), "expires_in": 600}, "", "  ")
		return os.WriteFile(filepath.Join(dir, uuid.NewString()+".json"), raw, 0600)
	}
	if cfg.Mode != "smtp" || cfg.Host == "" || cfg.From == "" {
		return errors.New("邮箱验证码服务未配置")
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	target := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", target)
	}
	if err != nil {
		return errors.New("连接邮件服务器失败")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if port != 465 {
		if err = client.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if cfg.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return errors.New("邮件服务器认证失败")
		}
	}
	if strings.ContainsAny(cfg.From, "\r\n") {
		return errors.New("invalid email.from")
	}
	if err = client.Mail(cfg.From); err != nil {
		return err
	}
	if err = client.Rcpt(address); err != nil {
		return err
	}
	stream, err := client.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stream, "From: %s\r\nTo: %s\r\nSubject: Account verification code\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nYour verification code is %s. It expires in 10 minutes.\r\n", cfg.From, address, code)
	if err != nil {
		return err
	}
	if err = stream.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *App) loginPayloadForRequest(c *gin.Context, u store.User, token string, isNew int) gin.H {
	payload := a.loginPayload(u, token, isNew)
	if app, ok := a.requestApplication(c); ok && app.GameClientID == "1067" {
		// Overseas email login has no mainland real-name/youth response fields.
		payload["real_switch"] = false
		payload["youth_switch"] = false
		payload["need_bind_phone"] = false
		if strings.Contains(u.Phone, "@") {
			payload["accounttype"] = 2
		}
		delete(payload, "youth_msg")
		delete(payload, "youth_report_interval")
		// A capture's IP geolocation describes that request, not the application.
		delete(payload, "location")
	}
	return payload
}
