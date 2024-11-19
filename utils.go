package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

const (
	// File permissions and paths
	DefaultKeyPermissions = 0600
	KeyStorePath          = "/var/lib/yourapp/keys/"
	MaxContentSize        = 10 * 1024 * 1024 // 10 MB

	// Content Types
	ContentTypeText      = "text"
	ContentTypeImage     = "image"
	ContentTypeJSON      = "json"
	ContentTypeMultipart = "multipart"

	// Visibility Levels
	VisibilityPublic  = "public"
	VisibilityPrivate = "private"
	VisibilityShared  = "shared"

	// Environments
	EnvironmentAPI     = "api"
	EnvironmentWeb     = "web"
	EnvironmentDesktop = "desktop"
	EnvironmentDiscord = "discord"

	// Common Providers
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderAdobe      = "adobe"
	ProviderMidjourney = "midjourney"

	// Capture Methods
	CaptureMethodAPIDirect     = "api-direct"
	CaptureMethodBrowserPlugin = "browser-plugin"
	CaptureMethodCLI           = "cli-tool"
	CaptureMethodSDK           = "sdk"
	CaptureMethodProxy         = "proxy"
	CaptureMethodIntercept     = "network-intercept"
	CaptureMethodDesktopPlugin = "desktop-plugin"

	// Algorithms
	HashAlgorithmSHA256     = "SHA256"
	SignatureAlgorithmECDSA = "ECDSA"
	EncryptionAlgoAES256GCM = "AES-256-GCM"
	CompressionAlgoGZIP     = "gzip"
)

// generateID creates a unique identifier with a prefix
func generateID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%x-%d", prefix, b, time.Now().UnixNano())
}

// encodeBase64 encodes data to base64
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 data
func decodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
