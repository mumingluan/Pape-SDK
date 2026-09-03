package storage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const signatureVersion = "OSS4-HMAC-SHA256"

type Client struct {
	endpoint        string
	publicBaseURL   string
	bucket          string
	region          string
	accessKeyID     string
	accessKeySecret string
	securityToken   string
	policyTTL       time.Duration
	maxUploadBytes  int64
	now             func() time.Time
	randomKey       func() (string, error)
}

type Options struct {
	Endpoint        string
	PublicBaseURL   string
	Bucket          string
	Region          string
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
	PolicyTTL       time.Duration
	MaxUploadBytes  int64
}

type AcquireRequest struct {
	ChannelID        string `json:"channel_id"`
	Category         string `json:"category"`
	OriginalFilename string `json:"original_filename"`
	ObjectName       string `json:"object_name,omitempty"`
	Extension        string `json:"extension,omitempty"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
}

type AcquireResponse struct {
	Address   string            `json:"address"`
	URL       string            `json:"url"`
	AddForm   map[string]string `json:"add_form"`
	AddHeader map[string]string `json:"add_header"`
}

func New(options Options) (*Client, error) {
	endpoint, err := absoluteURL(options.Endpoint, "storage.endpoint")
	if err != nil {
		return nil, err
	}
	publicBaseURL := strings.TrimSpace(options.PublicBaseURL)
	if publicBaseURL == "" {
		publicBaseURL = endpoint
	} else if publicBaseURL, err = absoluteURL(publicBaseURL, "storage.public_base_url"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.Region) == "" {
		return nil, errors.New("storage.region is required")
	}
	if strings.TrimSpace(options.AccessKeyID) == "" || strings.TrimSpace(options.AccessKeySecret) == "" {
		return nil, errors.New("storage.access_key_id and storage.access_key_secret are required")
	}
	if options.PolicyTTL <= 0 {
		options.PolicyTTL = 20 * time.Minute
	}
	if options.PolicyTTL > 7*24*time.Hour {
		return nil, errors.New("storage.policy_ttl_seconds cannot exceed 7 days")
	}
	if options.MaxUploadBytes <= 0 {
		options.MaxUploadBytes = 256 << 20
	}
	return &Client{
		endpoint: endpoint, publicBaseURL: publicBaseURL, bucket: strings.TrimSpace(options.Bucket),
		region: strings.TrimSpace(options.Region), accessKeyID: strings.TrimSpace(options.AccessKeyID),
		accessKeySecret: options.AccessKeySecret, securityToken: strings.TrimSpace(options.SecurityToken),
		policyTTL: options.PolicyTTL, maxUploadBytes: options.MaxUploadBytes,
		now: time.Now, randomKey: randomObjectID,
	}, nil
}

func (c *Client) Acquire(_ context.Context, request AcquireRequest) (*AcquireResponse, error) {
	category, err := cleanObjectKey(request.Category)
	if err != nil {
		return nil, errors.New("invalid object category")
	}
	objectName := strings.TrimSpace(request.ObjectName)
	if objectName != "" {
		if objectName, err = cleanObjectName(objectName); err != nil {
			return nil, errors.New("invalid object name")
		}
	} else {
		id, err := c.randomKey()
		if err != nil {
			return nil, fmt.Errorf("generate object key: %w", err)
		}
		objectName = id + safeExtension(request.Extension)
	}
	objectKey := category + "/" + objectName
	maxBytes := request.MaxBytes
	if maxBytes <= 0 || maxBytes > c.maxUploadBytes {
		maxBytes = c.maxUploadBytes
	}

	now := c.now().UTC()
	date := now.Format("20060102")
	timestamp := now.Format("20060102T150405Z")
	credential := c.accessKeyID + "/" + date + "/" + c.region + "/oss/aliyun_v4_request"
	conditions := []any{
		map[string]string{"key": objectKey},
		map[string]string{"x-oss-signature-version": signatureVersion},
		map[string]string{"x-oss-credential": credential},
		map[string]string{"x-oss-date": timestamp},
		[]any{"content-length-range", 0, maxBytes},
		map[string]string{"success_action_status": "200"},
	}
	if c.bucket != "" {
		conditions = append(conditions, map[string]string{"bucket": c.bucket})
	}
	if c.securityToken != "" {
		conditions = append(conditions, map[string]string{"x-oss-security-token": c.securityToken})
	}
	policyJSON, err := json.Marshal(map[string]any{
		"expiration": now.Add(c.policyTTL).Format("2006-01-02T15:04:05.000Z"),
		"conditions": conditions,
	})
	if err != nil {
		return nil, err
	}
	policy := base64.StdEncoding.EncodeToString(policyJSON)
	form := map[string]string{
		"key": objectKey, "policy": policy, "success_action_status": "200",
		"x-oss-signature-version": signatureVersion, "x-oss-credential": credential,
		"x-oss-date": timestamp, "x-oss-signature": signPolicy(c.accessKeySecret, date, c.region, policy),
		"x:extend": "",
	}
	if c.securityToken != "" {
		form["x-oss-security-token"] = c.securityToken
	}
	return &AcquireResponse{
		Address: c.endpoint, URL: objectURL(c.publicBaseURL, objectKey), AddForm: form,
		AddHeader: map[string]string{"Date": now.Format(http.TimeFormat)},
	}, nil
}

func signPolicy(secret, date, region, policy string) string {
	dateKey := hmacSHA256([]byte("aliyun_v4"+secret), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, "oss")
	signingKey := hmacSHA256(serviceKey, "aliyun_v4_request")
	return hex.EncodeToString(hmacSHA256(signingKey, policy))
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func absoluteURL(value, name string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must be an absolute HTTP(S) URL without query or fragment", name)
	}
	return value, nil
}

func cleanObjectKey(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsRune(value, '\x00') {
		return "", errors.New("invalid object key")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("invalid object key")
	}
	return clean, nil
}

func cleanObjectName(value string) (string, error) {
	clean, err := cleanObjectKey(value)
	if err != nil || strings.Contains(clean, "/") || clean != value {
		return "", errors.New("invalid object name")
	}
	return clean, nil
}

func safeExtension(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename != "" && !strings.Contains(filename, ".") {
		filename = "." + filename
	}
	extension := strings.ToLower(path.Ext(strings.ReplaceAll(filename, "\\", "/")))
	if len(extension) < 2 || len(extension) > 16 {
		return ""
	}
	for _, character := range extension[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return ""
		}
	}
	return extension
}

func objectURL(baseURL, key string) string {
	segments := strings.Split(key, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return strings.TrimRight(baseURL, "/") + "/" + strings.Join(segments, "/")
}

func randomObjectID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
