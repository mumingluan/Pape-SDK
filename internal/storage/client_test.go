package storage

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestAcquireBuildsAliyunOSSPostObjectV4Policy(t *testing.T) {
	client, err := New(Options{
		Endpoint: "https://example-bucket.oss-cn-hangzhou.aliyuncs.com", Bucket: "example-bucket",
		Region: "cn-hangzhou", AccessKeyID: "LTAIexample", AccessKeySecret: "secret",
		PolicyTTL: 20 * time.Minute, MaxUploadBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 9, 3, 8, 30, 0, 0, time.UTC) }
	client.randomKey = func() (string, error) { return "00112233445566778899aabbccddeeff", nil }
	response, err := client.Acquire(context.Background(), AcquireRequest{
		Category: "photo/a", OriginalFilename: "upload.bin", Extension: "bin", MaxBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantKey := "photo/a/00112233445566778899aabbccddeeff.bin"
	if response.Address != "https://example-bucket.oss-cn-hangzhou.aliyuncs.com" ||
		response.URL != response.Address+"/"+wantKey || response.AddForm["key"] != wantKey {
		t.Fatalf("response = %+v", response)
	}
	if response.AddForm["x-oss-signature-version"] != "OSS4-HMAC-SHA256" ||
		response.AddForm["x-oss-credential"] != "LTAIexample/20260903/cn-hangzhou/oss/aliyun_v4_request" ||
		response.AddForm["x-oss-security-token"] != "" {
		t.Fatalf("form = %+v", response.AddForm)
	}
	wantSignature := signPolicy("secret", "20260903", "cn-hangzhou", response.AddForm["policy"])
	if !hmac.Equal([]byte(response.AddForm["x-oss-signature"]), []byte(wantSignature)) {
		t.Fatal("invalid V4 policy signature")
	}
	raw, err := base64.StdEncoding.DecodeString(response.AddForm["policy"])
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil || policy["expiration"] != "2026-09-03T08:50:00.000Z" {
		t.Fatalf("policy = %s, err = %v", raw, err)
	}
}

func TestAcquireIncludesSTSSecurityToken(t *testing.T) {
	client, err := New(Options{
		Endpoint: "https://bucket.example", Region: "cn-hangzhou", AccessKeyID: "id",
		AccessKeySecret: "secret", SecurityToken: "sts-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Acquire(context.Background(), AcquireRequest{Category: "logs", ObjectName: "a.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if response.AddForm["x-oss-security-token"] != "sts-token" {
		t.Fatalf("form = %+v", response.AddForm)
	}
}
