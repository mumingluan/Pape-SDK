package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DBURI               string            `yaml:"db_uri"`
	DataDir             string            `yaml:"data_dir"`
	Sdk                 Service           `yaml:"sdk"`
	Login               LoginService      `yaml:"login"`
	UserCenter          AccessService     `yaml:"usercenter"`
	Game                Service           `yaml:"game"`
	Auth                Authentication    `yaml:"authentication"`
	Constants           Constants         `yaml:"constants"`
	UserCenterConstants Constants         `yaml:"usercenter_constants"`
	RealNameIdentity    RealNameIdentity  `yaml:"realname_identity"`
	Hosts               Hosts             `yaml:"hosts"`
	Parameters          map[string]string `yaml:"parameters"`
	Hotfix              Hotfix            `yaml:"hotfix"`
	SMS                 SMS               `yaml:"sms"`

	BaseDir string `yaml:"-"`
}

type Service struct {
	Enabled  bool   `yaml:"enabled"`
	BindHost string `yaml:"bindhost"`
	BindPort int    `yaml:"bindport"`
}

type LoginService struct {
	Service       `yaml:",inline"`
	AccessAddress string `yaml:"accessaddress"`
	AccessHost    string `yaml:"accesshost"`
}

type AccessService struct {
	Service       `yaml:",inline"`
	AccessAddress string `yaml:"accessaddress"`
}

type Authentication struct {
	RealPassword bool `yaml:"realpassword"`
	RealSMS      bool `yaml:"realsms"`
	SMSRegister  bool `yaml:"smsregister"`
}

type Constants struct {
	ClientID  int    `yaml:"client_id"`
	ClientKey string `yaml:"client_key"`
	AppID     string `yaml:"app_id"`
	AppKey    string `yaml:"app_key"`
	AESKey    string `yaml:"aes_key"`
}

type RealNameIdentity struct {
	RealName string `yaml:"realname"`
	RealID   string `yaml:"realid"`
}

type Hosts struct {
	API      string `yaml:"api"`
	Passport string `yaml:"passport"`
	APM      string `yaml:"apm"`
	Risk     string `yaml:"risk"`
	Web      string `yaml:"web"`
	Notice   string `yaml:"notice"`
}

type Hotfix struct {
	Proxy    bool   `yaml:"proxy"`
	ProxyURL string `yaml:"proxy_url"`
}

type SMS struct {
	Provider string    `yaml:"provider"`
	Aliyun   AliyunSMS `yaml:"aliyun"`
}

type AliyunSMS struct {
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	RegionID        string `yaml:"region_id"`
	SignName        string `yaml:"sign_name"`
	TemplateCode    string `yaml:"template_code"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cfg.BaseDir = filepath.Dir(abs)
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if cfg.Constants.ClientID == 0 {
		cfg.Constants.ClientID = 1068
	}
	if cfg.UserCenterConstants.ClientID == 0 {
		cfg.UserCenterConstants.ClientID = 1003
	}
	if cfg.UserCenterConstants.ClientKey == "" {
		cfg.UserCenterConstants.ClientKey = "jshR3bIqYUSF"
	}
	if cfg.UserCenterConstants.AppID == "" {
		cfg.UserCenterConstants.AppID = "1010013"
	}
	if cfg.UserCenterConstants.AppKey == "" {
		cfg.UserCenterConstants.AppKey = "NsalbZh76U8VGJp1"
	}
	if cfg.UserCenterConstants.AESKey == "" {
		cfg.UserCenterConstants.AESKey = "ZTM7fu0xYnzkE5Km"
	}
	if cfg.RealNameIdentity.RealName == "" {
		cfg.RealNameIdentity.RealName = "已认证"
	}
	if cfg.RealNameIdentity.RealID == "" {
		cfg.RealNameIdentity.RealID = "110101199001010010"
	}
	if cfg.Login.AccessAddress == "" {
		cfg.Login.AccessAddress = cfg.Login.AccessHost
	}
	return &cfg, nil
}

func (c *Config) Resolve(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.BaseDir, path)
}

func (c *Config) DataPath(name string) string {
	return c.Resolve(filepath.Join(c.DataDir, name))
}
