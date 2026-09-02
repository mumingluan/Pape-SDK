package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	adminToken string
	http       *http.Client
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

func New(baseURL, adminToken string, timeout time.Duration) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("storage.base_url must be an absolute HTTP(S) URL")
	}
	if strings.TrimSpace(adminToken) == "" {
		return nil, errors.New("storage.admin_token is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{baseURL: baseURL, adminToken: adminToken, http: &http.Client{Timeout: timeout}}, nil
}

func (c *Client) Acquire(ctx context.Context, request AcquireRequest) (*AcquireResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/upload-tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+c.adminToken)
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("request storage upload token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return nil, fmt.Errorf("storage upload token returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	var acquired AcquireResponse
	if err := json.NewDecoder(response.Body).Decode(&acquired); err != nil {
		return nil, fmt.Errorf("decode storage upload token: %w", err)
	}
	if acquired.Address == "" || acquired.URL == "" || acquired.AddForm["key"] == "" || acquired.AddForm["x-oss-security-token"] == "" {
		return nil, errors.New("storage returned an incomplete upload token")
	}
	return &acquired, nil
}
