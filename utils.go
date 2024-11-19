package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration values for the key management system
type Config struct {
	// File-related settings
	KeyStorePath        string      `json:"key_store_path"`
	KeyPermissions      os.FileMode `json:"key_permissions"`
	KeyStorePermissions os.FileMode `json:"key_store_permissions"`
	MaxContentSize      int64       `json:"max_content_size"`

	// Feature flags and operational settings
	Environment   string `json:"environment"`
	Provider      string `json:"provider"`
	CaptureMethod string `json:"capture_method"`

	// Cryptographic settings
	HashAlgorithm        string `json:"hash_algorithm"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	EncryptionAlgorithm  string `json:"encryption_algorithm"`
	CompressionAlgorithm string `json:"compression_algorithm"`
}

// Constants representing valid configuration values
const (
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

	// Default Algorithm Values
	DefaultHashAlgorithm        = "SHA256"
	DefaultSignatureAlgorithm   = "ECDSA"
	DefaultEncryptionAlgorithm  = "AES-256-GCM"
	DefaultCompressionAlgorithm = "gzip"
)

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		KeyStorePath:         "/var/lib/yourapp/keys/",
		KeyPermissions:       0600,
		KeyStorePermissions:  0700,
		MaxContentSize:       10 * 1024 * 1024, // 10 MB
		Environment:          EnvironmentAPI,
		Provider:             ProviderOpenAI,
		CaptureMethod:        CaptureMethodAPIDirect,
		HashAlgorithm:        DefaultHashAlgorithm,
		SignatureAlgorithm:   DefaultSignatureAlgorithm,
		EncryptionAlgorithm:  DefaultEncryptionAlgorithm,
		CompressionAlgorithm: DefaultCompressionAlgorithm,
	}
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() *Config {
	config := DefaultConfig()

	if path := os.Getenv("KEY_STORE_PATH"); path != "" {
		config.KeyStorePath = path
	}

	if perm := os.Getenv("KEY_PERMISSIONS"); perm != "" {
		if parsed, err := strconv.ParseUint(perm, 8, 32); err == nil {
			config.KeyPermissions = os.FileMode(parsed)
		}
	}

	if perm := os.Getenv("KEY_STORE_PERMISSIONS"); perm != "" {
		if parsed, err := strconv.ParseUint(perm, 8, 32); err == nil {
			config.KeyStorePermissions = os.FileMode(parsed)
		}
	}

	if size := os.Getenv("MAX_CONTENT_SIZE"); size != "" {
		if parsed, err := strconv.ParseInt(size, 10, 64); err == nil {
			config.MaxContentSize = parsed
		}
	}

	if env := os.Getenv("ENVIRONMENT"); env != "" {
		config.Environment = env
	}

	if provider := os.Getenv("PROVIDER"); provider != "" {
		config.Provider = provider
	}

	if method := os.Getenv("CAPTURE_METHOD"); method != "" {
		config.CaptureMethod = method
	}

	if algo := os.Getenv("HASH_ALGORITHM"); algo != "" {
		config.HashAlgorithm = algo
	}

	if algo := os.Getenv("SIGNATURE_ALGORITHM"); algo != "" {
		config.SignatureAlgorithm = algo
	}

	if algo := os.Getenv("ENCRYPTION_ALGORITHM"); algo != "" {
		config.EncryptionAlgorithm = algo
	}

	if algo := os.Getenv("COMPRESSION_ALGORITHM"); algo != "" {
		config.CompressionAlgorithm = algo
	}

	return config
}

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

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.KeyStorePath == "" {
		return fmt.Errorf("key store path cannot be empty")
	}

	if c.KeyPermissions == 0 {
		return fmt.Errorf("invalid key permissions")
	}

	if c.KeyStorePermissions == 0 {
		return fmt.Errorf("invalid key store permissions")
	}

	if c.MaxContentSize <= 0 {
		return fmt.Errorf("max content size must be positive")
	}

	return nil
}
