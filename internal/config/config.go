package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GameConfigDirs      map[string]string `yaml:"game_config_dirs"`
	DBURI               string            `yaml:"db_uri"`
	ConfigDir           string            `yaml:"config_dir"`
	PatchList           PatchList         `yaml:"patchlist"`
	Sdk                 Service           `yaml:"sdk"`
	UserCenter          AccessService     `yaml:"user_center"`
	Inner               InnerService      `yaml:"inner_api"`
	BOOIInner           map[uint32]Peer   `yaml:"booi_inner"`
	Storage             Storage           `yaml:"storage"`
	Proxy               Proxy             `yaml:"proxy"`
	Auth                Authentication    `yaml:"authentication"`
	Constants           Constants         `yaml:"-"`
	DefaultApplication  string            `yaml:"default_application"`
	UserCenterConstants Constants         `yaml:"user_center_constants"`
	RealNameIdentity    RealNameIdentity  `yaml:"real_name_identity"`
	Hosts               Hosts             `yaml:"hosts"`
	SMS                 SMS               `yaml:"sms"`

	Applications map[string]Application `yaml:"applications"`
	Email        Email                  `yaml:"email"`
	BaseDir      string                 `yaml:"-"`
}

type PatchList struct {
	Passthrough bool `yaml:"passthrough"`
}

type Service struct {
	Enabled  bool   `yaml:"enabled"`
	BindHost string `yaml:"bind_host"`
	BindPort int    `yaml:"bind_port"`
}

type InnerService struct {
	Service   `yaml:",inline"`
	AuthToken string `yaml:"auth_token"`
}

type Peer struct {
	BaseURL        string `yaml:"base_url"`
	AuthToken      string `yaml:"auth_token"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

type Storage struct {
	Endpoint         string `yaml:"endpoint"`
	PublicBaseURL    string `yaml:"public_base_url"`
	Bucket           string `yaml:"bucket"`
	Region           string `yaml:"region"`
	AccessKeyID      string `yaml:"access_key_id"`
	AccessKeySecret  string `yaml:"access_key_secret"`
	SecurityToken    string `yaml:"security_token"`
	PolicyTTLSeconds int    `yaml:"policy_ttl_seconds"`
	MaxUploadBytes   int64  `yaml:"max_upload_bytes"`
	ProxyBaseURL     string `yaml:"proxy_base_url"`
	PublicHost       string `yaml:"public_host"`
}

type Proxy struct {
	Enabled                bool   `yaml:"enabled"`
	BindHost               string `yaml:"bind_host"`
	BindPort               int    `yaml:"bind_port"`
	UseHTTP2               bool   `yaml:"use_http2"`
	PassthroughAllUnknown  bool   `yaml:"passthrough_all_unknown"`
	PassthroughGameAddress bool   `yaml:"passthrough_game_address"`
	CAPrivateKeyPath       string `yaml:"ca_private_key_path"`
	CACertificatePath      string `yaml:"ca_certificate_path"`
	CollectRoute           bool   `yaml:"collect_route"`
}

type AccessService struct {
	Service       `yaml:",inline"`
	AccessAddress string `yaml:"access_address"`
}

type Authentication struct {
	RealPassword    bool `yaml:"real_password"`
	RealSMS         bool `yaml:"real_sms"`
	AllowRegister   bool `yaml:"allow_register"`
	SMSOnlyRegister bool `yaml:"sms_only_register"`
}

type Constants struct {
	ClientID  int    `yaml:"client_id"`
	ClientKey string `yaml:"client_key"`
	AppID     string `yaml:"app_id"`
	AppKey    string `yaml:"app_key"`
	AESKey    string `yaml:"aes_key"`
}

type RealNameIdentity struct {
	RealName string `yaml:"real_name"`
	RealID   string `yaml:"real_id"`
}

type Hosts struct {
	API      string `yaml:"api"`
	Passport string `yaml:"passport"`
	APM      string `yaml:"apm"`
	Risk     string `yaml:"risk"`
	Web      string `yaml:"web"`
	Notice   string `yaml:"notice"`
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
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cfg.BaseDir = filepath.Dir(abs)
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = "./config"
	}
	if cfg.Proxy.BindHost == "" {
		cfg.Proxy.BindHost = "127.0.0.1"
	}
	if cfg.Proxy.BindPort == 0 {
		cfg.Proxy.BindPort = 8888
	}
	if cfg.Inner.BindHost == "" {
		cfg.Inner.BindHost = "127.0.0.1"
	}
	if cfg.Inner.BindPort == 0 {
		cfg.Inner.BindPort = 18081
	}
	for serverID, peer := range cfg.BOOIInner {
		if peer.TimeoutSeconds == 0 {
			peer.TimeoutSeconds = 5
			cfg.BOOIInner[serverID] = peer
		}
	}
	if cfg.Storage.PolicyTTLSeconds == 0 {
		cfg.Storage.PolicyTTLSeconds = 20 * 60
	}
	if cfg.Storage.MaxUploadBytes == 0 {
		cfg.Storage.MaxUploadBytes = 256 << 20
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
	seenClients := map[int]bool{}
	for id, app := range cfg.Applications {
		if app.AppID == "" {
			app.AppID = id
		}
		if app.AppID != id || app.ClientID == 0 || app.AppKey == "" || app.AESKey == "" {
			return nil, fmt.Errorf("invalid application configuration: %s", id)
		}
		if seenClients[app.ClientID] {
			return nil, fmt.Errorf("duplicate application client_id: %d", app.ClientID)
		}
		seenClients[app.ClientID] = true
		cfg.Applications[id] = app
	}
	if cfg.DefaultApplication == "" && len(cfg.Applications) == 1 {
		for id := range cfg.Applications {
			cfg.DefaultApplication = id
		}
	}
	if len(cfg.Applications) > 0 || cfg.DefaultApplication != "" {
		app, ok := cfg.Applications[cfg.DefaultApplication]
		if !ok {
			return nil, fmt.Errorf("default_application must name a configured application")
		}
		cfg.Constants = app.Constants
	}
	return &cfg, nil
}

func (c *Config) Resolve(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.BaseDir, path)
}

func (c *Config) ConfigPath(name string) string {
	return c.Resolve(filepath.Join(c.ConfigDir, name))
}

type Application struct {
	Constants    `yaml:",inline"`
	ConfigDir    string `yaml:"config_dir"`
	Region       string `yaml:"region"`
	Channel      string `yaml:"channel"`
	GameClientID string `yaml:"game_client_id"`
	API          string `yaml:"api"`
}
type Email struct {
	Mode      string `yaml:"mode"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	From      string `yaml:"from"`
	OutboxDir string `yaml:"outbox_dir"`
}

func (c *Config) Application(appID, clientID, region, channel string) (Application, bool) {
	if appID != "" {
		app, ok := c.Applications[appID]
		return app, ok
	}
	var found Application
	matches := 0
	for _, app := range c.Applications {
		if clientID == fmt.Sprint(app.ClientID) {
			return app, true
		}
		if clientID == app.GameClientID && (channel != "" && channel == app.Channel || channel == "" && region != "" && region == app.Region) {
			found = app
			matches++
		}
	}
	return found, matches == 1
}
func (c *Config) ApplicationConfigPath(app Application, name string) string {
	if app.ConfigDir != "" {
		return c.Resolve(filepath.Join(app.ConfigDir, name))
	}
	return c.ConfigPath(name)
}
