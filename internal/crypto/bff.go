package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type BFF struct {
	AppID  string
	AppKey string
	AESKey string
}

type params struct {
	Algorithm string
	Mode      string
	Encoder   string
	Key       []byte
	IV        []byte
	BlockSize int
}

func (b BFF) EncryptData(obj any, timestamp int64) (string, error) {
	if b.isAccountCenter() {
		return b.encryptAccountCenterData(obj)
	}
	p := b.params(timestamp)
	plain, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	block, err := newBlock(p)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plain, p.BlockSize)
	encrypted := make([]byte, len(padded))
	if p.Mode == "ECB" {
		ecbEncrypt(block, encrypted, padded)
	} else {
		cipher.NewCBCEncrypter(block, p.IV).CryptBlocks(encrypted, padded)
	}
	if p.Encoder == "HEX" {
		return hex.EncodeToString(encrypted), nil
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (b BFF) DecryptData(value string, timestamp int64) (map[string]string, error) {
	if b.isAccountCenter() {
		return b.decryptAccountCenterData(value)
	}
	p := b.params(timestamp)
	out, err := b.decryptDataWithParams(value, p)
	if err == nil {
		return out, nil
	}
	alt := p
	if alt.Encoder == "HEX" {
		alt.Encoder = "BASE64"
	} else {
		alt.Encoder = "HEX"
	}
	alt = b.paramsWithEncoder(timestamp, alt.Encoder)
	out, altErr := b.decryptDataWithParams(value, alt)
	if altErr == nil {
		return out, nil
	}
	return nil, err
}

func (b BFF) isAccountCenter() bool {
	return b.AppID == "1010013"
}

func (b BFF) encryptAccountCenterData(obj any) (string, error) {
	plain, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(b.AESKey))
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plain, block.BlockSize())
	encrypted := make([]byte, len(padded))
	iv := []byte(b.AESKey[:block.BlockSize()])
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (b BFF) decryptAccountCenterData(value string) (map[string]string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(value, " ", "+"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(b.AESKey))
	if err != nil {
		return nil, err
	}
	if len(encrypted)%block.BlockSize() != 0 {
		return nil, errors.New("encrypted data is not block aligned")
	}
	plain := make([]byte, len(encrypted))
	iv := []byte(b.AESKey[:block.BlockSize()])
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encrypted)
	plain, err = pkcs7Unpad(plain, block.BlockSize())
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(plain))), &decoded); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(decoded))
	for k, v := range decoded {
		out[k] = fmt.Sprint(v)
	}
	return out, nil
}

func (b BFF) decryptDataWithParams(value string, p params) (map[string]string, error) {
	var encrypted []byte
	var err error
	if p.Encoder == "HEX" {
		encrypted, err = hex.DecodeString(value)
	} else {
		encrypted, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, err
	}
	block, err := newBlock(p)
	if err != nil {
		return nil, err
	}
	if len(encrypted)%p.BlockSize != 0 {
		return nil, errors.New("encrypted data is not block aligned")
	}
	plain := make([]byte, len(encrypted))
	if p.Mode == "ECB" {
		ecbDecrypt(block, plain, encrypted)
	} else {
		cipher.NewCBCDecrypter(block, p.IV).CryptBlocks(plain, encrypted)
	}
	plain, err = pkcs7Unpad(plain, p.BlockSize)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(plain))), &decoded); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(decoded))
	for k, v := range decoded {
		out[k] = fmt.Sprint(v)
	}
	return out, nil
}

func (b BFF) Sign(outer map[string]string) string {
	keys := make([]string, 0, len(outer))
	for k := range outer {
		if k != "sign" && k != "sig" && k != "data" && outer[k] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+outer[k])
	}
	mac := hmac.New(md5.New, []byte(b.AppKey))
	mac.Write([]byte(strings.Join(parts, "&")))
	return hex.EncodeToString(mac.Sum(nil))
}

func (b BFF) PassportData(obj any, timestamp int64) (any, error) {
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	return b.EncryptData(obj, timestamp)
}

func (b BFF) params(timestamp int64) params {
	encoder := "HEX"
	if (timestamp%10)&1 == 1 {
		encoder = "BASE64"
	}
	return b.paramsWithEncoder(timestamp, encoder)
}

func (b BFF) paramsWithEncoder(timestamp int64, encoder string) params {
	algorithm := "DES"
	if len(b.AESKey) > 0 && (b.AESKey[0]&1) == 1 {
		algorithm = "AES"
	}
	mode := "ECB"
	if len(b.AppID) > 0 && (b.AppID[len(b.AppID)-1]&1) == 1 {
		mode = "CBC"
	}
	src := strings.Join([]string{b.AESKey, algorithm, mode, "PKCS7Padding", encoder, b.AppID, strconv.FormatInt(timestamp, 10)}, "#")
	sum := md5.Sum([]byte(src))
	material := hex.EncodeToString(sum[:])
	keySize := 8
	blockSize := 8
	if algorithm == "AES" {
		keySize = 32
		blockSize = 16
	}
	key := []byte(material[:keySize])
	var iv []byte
	if mode != "ECB" {
		iv = []byte(material[:blockSize])
	}
	return params{Algorithm: algorithm, Mode: mode, Encoder: encoder, Key: key, IV: iv, BlockSize: blockSize}
}

func newBlock(p params) (cipher.Block, error) {
	if p.Algorithm == "DES" {
		return des.NewCipher(p.Key)
	}
	return aes.NewCipher(p.Key)
}

func pkcs7Pad(data []byte, size int) []byte {
	pad := size - len(data)%size
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, size int) ([]byte, error) {
	if len(data) == 0 || len(data)%size != 0 {
		return nil, errors.New("invalid pkcs7 data")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > size || pad > len(data) {
		return nil, errors.New("invalid pkcs7 padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid pkcs7 padding")
		}
	}
	return data[:len(data)-pad], nil
}

func ecbEncrypt(block cipher.Block, dst, src []byte) {
	size := block.BlockSize()
	for len(src) > 0 {
		block.Encrypt(dst[:size], src[:size])
		src = src[size:]
		dst = dst[size:]
	}
}

func ecbDecrypt(block cipher.Block, dst, src []byte) {
	size := block.BlockSize()
	for len(src) > 0 {
		block.Decrypt(dst[:size], src[:size])
		src = src[size:]
		dst = dst[size:]
	}
}
