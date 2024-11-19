package core

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
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
	keyStore *KeyStore
}

// NewContentProcessor creates a new content processor
func NewContentProcessor(keyStore *KeyStore) *ContentProcessor {
	return &ContentProcessor{
		keyStore: keyStore,
	}
}

// ProcessContent handles both compression and encryption of content
func (cp *ContentProcessor) ProcessContent(content *Content) error {
	if err := CompressContent(content); err != nil {
		return &OpenProofError{Op: "compress_content", Err: err}
	}

	if err := cp.EncryptContent(content); err != nil {
		return &OpenProofError{Op: "encrypt_content", Err: err}
	}

	return nil
}

// EncryptContent encrypts the content using AES-256-GCM
func (cp *ContentProcessor) EncryptContent(content *Content) error {
	key, err := cp.keyStore.GetActiveKey()
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	data := []byte(content.Data)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	content.Data = encodeBase64(ciphertext)
	content.EncryptionAlgo = EncryptionAlgoAES256GCM
	content.EncryptionKeyID = cp.keyStore.ActiveKeyID
	content.Encoding = "base64"

	return nil
}

// DecryptContent decrypts the content
func (cp *ContentProcessor) DecryptContent(content *Content) error {
	if content.EncryptionAlgo != EncryptionAlgoAES256GCM {
		return fmt.Errorf("unsupported encryption algorithm: %s", content.EncryptionAlgo)
	}

	key, err := cp.keyStore.GetActiveKey()
	if err != nil {
		return err
	}

	ciphertext, err := decodeBase64(content.Data)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create gcm: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return fmt.Errorf("invalid ciphertext size")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt content: %w", err)
	}

	content.Data = string(plaintext)
	content.EncryptionAlgo = ""
	content.EncryptionKeyID = ""
	content.Encoding = ""

	return nil
}

// CompressContent compresses the content using gzip
func CompressContent(content *Content) error {
	if content.Compressed {
		return nil
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write([]byte(content.Data)); err != nil {
		return fmt.Errorf("compress write: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("compress close: %w", err)
	}

	content.Data = encodeBase64(buf.Bytes())
	content.Encoding = "base64"
	content.Compressed = true
	content.CompressionAlgo = CompressionAlgoGZIP

	return nil
}

// DecompressContent decompresses the content
func DecompressContent(content *Content) error {
	if !content.Compressed {
		return nil
	}

	data, err := decodeBase64(content.Data)
	if err != nil {
		return fmt.Errorf("decode content: %w", err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer reader.Close()

	decompressed, err := ioutil.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("decompress content: %w", err)
	}

	content.Data = string(decompressed)
	content.Compressed = false
	content.CompressionAlgo = ""
	content.Encoding = ""

	return nil
}
