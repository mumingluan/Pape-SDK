package sms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysmsapi "github.com/alibabacloud-go/dysmsapi-20170525/v4/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"

	"pape-sdk/server/internal/config"
)

type Provider interface {
	SendCode(ctx context.Context, phone, code, scene string) error
}

type Noop struct{}

func (Noop) SendCode(_ context.Context, phone, code, scene string) error {
	log.Printf("[sms] noop scene=%s phone=%s code=%s", scene, phone, code)
	return nil
}

func New(cfg config.SMS) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "", "noop", "log":
		return Noop{}, nil
	case "aliyun":
		return NewAliyun(cfg.Aliyun)
	default:
		return nil, fmt.Errorf("不支持的短信服务商：%s", cfg.Provider)
	}
}

type Aliyun struct {
	client       *dysmsapi.Client
	signName     string
	templateCode string
}

func NewAliyun(cfg config.AliyunSMS) (*Aliyun, error) {
	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" || cfg.SignName == "" || cfg.TemplateCode == "" {
		return nil, errors.New("阿里云短信配置不完整")
	}
	endpoint := "dysmsapi.aliyuncs.com"
	client, err := dysmsapi.NewClient(&openapi.Config{
		AccessKeyId:     tea.String(cfg.AccessKeyID),
		AccessKeySecret: tea.String(cfg.AccessKeySecret),
		RegionId:        tea.String(cfg.RegionID),
		Endpoint:        tea.String(endpoint),
	})
	if err != nil {
		return nil, err
	}
	return &Aliyun{client: client, signName: cfg.SignName, templateCode: cfg.TemplateCode}, nil
}

func (a *Aliyun) SendCode(ctx context.Context, phone, code, scene string) error {
	param, _ := json.Marshal(map[string]string{"code": code})
	req := &dysmsapi.SendSmsRequest{
		PhoneNumbers:  tea.String(phone),
		SignName:      tea.String(a.signName),
		TemplateCode:  tea.String(a.templateCode),
		TemplateParam: tea.String(string(param)),
	}
	resp, err := a.client.SendSmsWithOptions(req, &util.RuntimeOptions{})
	if err != nil {
		return err
	}
	if resp == nil || resp.Body == nil || resp.Body.Code == nil {
		return errors.New("阿里云短信返回为空")
	}
	if *resp.Body.Code != "OK" {
		msg := ""
		if resp.Body.Message != nil {
			msg = *resp.Body.Message
		}
		return fmt.Errorf("短信发送失败：%s", msg)
	}
	_ = ctx
	log.Printf("[sms] aliyun sent scene=%s phone=%s bizId=%s", scene, phone, tea.StringValue(resp.Body.BizId))
	return nil
}
