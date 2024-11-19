// content.go
package core

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Content represents any type of data with encryption and compression support
type Content struct {
	Type            string                 `json:"type"`
	Format          string                 `json:"format,omitempty"`
	Data            string                 `json:"data"`
	Encoding        string                 `json:"encoding,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	EncryptionKeyID string                 `json:"encryption_key_id,omitempty"`
	EncryptionAlgo  string                 `json:"encryption_algo,omitempty"`
	Compressed      bool                   `json:"compressed,omitempty"`
	CompressionAlgo string                 `json:"compression_algo,omitempty"`
}

// ContentProcessor handles encryption and compression of content
type ContentProcessor struct {
	config   *Config
	keyStore *KeyStore
}

// NewContentProcessor creates a new content processor
func NewContentProcessor(config *Config, keyStore *KeyStore) *ContentProcessor {
	return &ContentProcessor{
		config:   config,
		keyStore: keyStore,
	}
}

// ProcessContent handles both compression and encryption of content
func (cp *ContentProcessor) ProcessContent(content *Content) error {
	// Validate content size
	if len(content.Data) > int(cp.config.MaxContentSize) {
		return &OpenProofError{
			Op:  "validate_content_size",
			Err: fmt.Errorf("content size exceeds maximum allowed size of %d bytes", cp.config.MaxContentSize),
		}
	}

	if err := cp.CompressContent(content); err != nil {
		return &OpenProofError{Op: "compress_content", Err: err}
	}

	if err := cp.EncryptContent(content); err != nil {
		return &OpenProofError{Op: "encrypt_content", Err: err}
	}

	return nil
}

// EncryptContent encrypts the content using the configured encryption algorithm
func (cp *ContentProcessor) EncryptContent(content *Content) error {
	key, err := cp.keyStore.GetActiveKey()
	if err != nil {
		return err
	}

	// Verify encryption algorithm is supported
	if cp.config.EncryptionAlgorithm != DefaultEncryptionAlgorithm {
		return &OpenProofError{
			Op:  "validate_encryption_algo",
			Err: fmt.Errorf("unsupported encryption algorithm: %s", cp.config.EncryptionAlgorithm),
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return &OpenProofError{Op: "create_cipher", Err: err}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return &OpenProofError{Op: "create_gcm", Err: err}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return &OpenProofError{Op: "generate_nonce", Err: err}
	}

	data := []byte(content.Data)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	content.Data = encodeBase64(ciphertext)
	content.EncryptionAlgo = cp.config.EncryptionAlgorithm
	content.EncryptionKeyID = cp.keyStore.ActiveKeyID
	content.Encoding = "base64"

	return nil
}

// DecryptContent decrypts the content
func (cp *ContentProcessor) DecryptContent(content *Content) error {
	if content.EncryptionAlgo != cp.config.EncryptionAlgorithm {
		return &OpenProofError{
			Op:  "validate_decryption_algo",
			Err: fmt.Errorf("unsupported encryption algorithm: %s", content.EncryptionAlgo),
		}
	}

	key, err := cp.keyStore.GetActiveKey()
	if err != nil {
		return err
	}

	ciphertext, err := decodeBase64(content.Data)
	if err != nil {
		return &OpenProofError{Op: "decode_ciphertext", Err: err}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return &OpenProofError{Op: "create_cipher", Err: err}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return &OpenProofError{Op: "create_gcm", Err: err}
	}

	if len(ciphertext) < gcm.NonceSize() {
		return &OpenProofError{Op: "validate_ciphertext", Err: fmt.Errorf("invalid ciphertext size")}
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return &OpenProofError{Op: "decrypt_content", Err: err}
	}

	content.Data = string(plaintext)
	content.EncryptionAlgo = ""
	content.EncryptionKeyID = ""
	content.Encoding = ""

	return nil
}

// CompressContent compresses the content using the configured compression algorithm
func (cp *ContentProcessor) CompressContent(content *Content) error {
	if content.Compressed {
		return nil
	}

	// Verify compression algorithm is supported
	if cp.config.CompressionAlgorithm != DefaultCompressionAlgorithm {
		return &OpenProofError{
			Op:  "validate_compression_algo",
			Err: fmt.Errorf("unsupported compression algorithm: %s", cp.config.CompressionAlgorithm),
		}
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write([]byte(content.Data)); err != nil {
		return &OpenProofError{Op: "compress_write", Err: err}
	}

	if err := writer.Close(); err != nil {
		return &OpenProofError{Op: "compress_close", Err: err}
	}

	content.Data = encodeBase64(buf.Bytes())
	content.Encoding = "base64"
	content.Compressed = true
	content.CompressionAlgo = cp.config.CompressionAlgorithm

	return nil
}

// DecompressContent decompresses the content
func (cp *ContentProcessor) DecompressContent(content *Content) error {
	if !content.Compressed {
		return nil
	}

	if content.CompressionAlgo != cp.config.CompressionAlgorithm {
		return &OpenProofError{
			Op:  "validate_decompression_algo",
			Err: fmt.Errorf("unsupported compression algorithm: %s", content.CompressionAlgo),
		}
	}

	data, err := decodeBase64(content.Data)
	if err != nil {
		return &OpenProofError{Op: "decode_compressed_content", Err: err}
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return &OpenProofError{Op: "create_gzip_reader", Err: err}
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return &OpenProofError{Op: "decompress_content", Err: err}
	}

	content.Data = string(decompressed)
	content.Compressed = false
	content.CompressionAlgo = ""
	content.Encoding = ""

	return nil
}
