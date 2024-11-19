// keys.go
package core

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// KeyStore manages encryption keys with support for key rotation
type KeyStore struct {
	config      *Config
	ActiveKeyID string
	Keys        map[string]KeyMetadata
	sync.RWMutex
}

// KeyMetadata holds information about encryption keys
type KeyMetadata struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
	FilePath  string    `json:"-"` // Not serialized to JSON
}

// KeyData represents the actual key material and metadata
type KeyData struct {
	KeyMetadata
	Material []byte `json:"-"` // Raw key material, not serialized to JSON
}

// NewKeyStore initializes a new key store with the provided configuration
func NewKeyStore(config *Config) (*KeyStore, error) {
	if err := config.Validate(); err != nil {
		return nil, &OpenProofError{Op: "validate_config", Err: err}
	}

	if err := os.MkdirAll(config.KeyStorePath, config.KeyStorePermissions); err != nil {
		return nil, &OpenProofError{Op: "create_keystore", Err: err}
	}

	ks := &KeyStore{
		config: config,
		Keys:   make(map[string]KeyMetadata),
	}

	if err := ks.loadKeys(); err != nil {
		return nil, err
	}

	if len(ks.Keys) == 0 {
		if _, err := ks.GenerateKey(); err != nil {
			return nil, &OpenProofError{Op: "generate_initial_key", Err: err}
		}
	}

	return ks, nil
}

// GenerateKey creates and stores a new encryption key
func (ks *KeyStore) GenerateKey() (string, error) {
	ks.Lock()
	defer ks.Unlock()

	// Deactivate existing active keys
	for id, key := range ks.Keys {
		if key.Status == "active" {
			key.Status = "inactive"
			ks.Keys[id] = key
			keyData, err := ks.loadKey(key.FilePath)
			if err != nil {
				return "", &OpenProofError{Op: "load_existing_active_key", Err: err}
			}
			keyData.Status = "inactive"
			if err := ks.saveKey(*keyData); err != nil {
				return "", &OpenProofError{Op: "save_existing_active_key", Err: err}
			}
		}
	}

	keyID := generateID("key")
	keyMaterial := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		return "", &OpenProofError{Op: "generate_key_material", Err: err}
	}

	metadata := KeyMetadata{
		ID:        keyID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0), // 1 year expiration
		Status:    "active",
		FilePath:  filepath.Join(ks.config.KeyStorePath, fmt.Sprintf("%s.key", keyID)),
	}

	keyData := KeyData{
		KeyMetadata: metadata,
		Material:    keyMaterial,
	}

	if err := ks.saveKey(keyData); err != nil {
		return "", err
	}

	ks.Keys[keyID] = metadata
	ks.ActiveKeyID = keyID

	return keyID, nil
}

// saveKey saves a key to disk
func (ks *KeyStore) saveKey(keyData KeyData) error {
	file, err := os.OpenFile(keyData.FilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ks.config.KeyPermissions)
	if err != nil {
		return &OpenProofError{Op: "create_key_file", Err: err}
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	storage := struct {
		KeyMetadata
		Material string `json:"material"`
	}{
		KeyMetadata: keyData.KeyMetadata,
		Material:    encodeBase64(keyData.Material),
	}

	if err := json.NewEncoder(file).Encode(storage); err != nil {
		return &OpenProofError{Op: "write_key_file", Err: err}
	}

	return nil
}

// GetActiveKey returns the currently active encryption key
func (ks *KeyStore) GetActiveKey() ([]byte, error) {
	ks.RLock()
	defer ks.RUnlock()

	if ks.ActiveKeyID == "" {
		return nil, &OpenProofError{Op: "get_active_key", Err: fmt.Errorf("no active key")}
	}

	keyData, err := ks.loadKey(filepath.Join(ks.config.KeyStorePath, fmt.Sprintf("%s.key", ks.ActiveKeyID)))
	if err != nil {
		return nil, err
	}

	return keyData.Material, nil
}

// loadKey loads a key from disk
func (ks *KeyStore) loadKey(path string) (*KeyData, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &OpenProofError{Op: "open_key_file", Err: err}
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	var storage struct {
		KeyMetadata
		Material string `json:"material"`
	}

	if err := json.NewDecoder(file).Decode(&storage); err != nil {
		return nil, &OpenProofError{Op: "read_key_file", Err: err}
	}

	material, err := decodeBase64(storage.Material)
	if err != nil {
		return nil, &OpenProofError{Op: "decode_key_material", Err: err}
	}

	storage.KeyMetadata.FilePath = path

	return &KeyData{
		KeyMetadata: storage.KeyMetadata,
		Material:    material,
	}, nil
}

// loadKeys loads all keys from the key store directory
func (ks *KeyStore) loadKeys() error {
	ks.Lock()
	defer ks.Unlock()

	files, err := os.ReadDir(ks.config.KeyStorePath)
	if err != nil {
		return &OpenProofError{Op: "read_keystore", Err: err}
	}

	activeKeys := 0
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".key" {
			continue
		}

		keyData, err := ks.loadKey(filepath.Join(ks.config.KeyStorePath, file.Name()))
		if err != nil {
			return err
		}

		ks.Keys[keyData.ID] = keyData.KeyMetadata
		if keyData.Status == "active" {
			activeKeys++
			ks.ActiveKeyID = keyData.ID
		}
	}

	if activeKeys > 1 {
		return &OpenProofError{Op: "load_keys", Err: fmt.Errorf("multiple active keys found")}
	}

	return nil
}

// RotateKey creates a new key and marks the old one as inactive
func (ks *KeyStore) RotateKey() (string, error) {
	ks.Lock()
	defer ks.Unlock()

	oldKeyID := ks.ActiveKeyID

	newKeyID, err := ks.GenerateKey()
	if err != nil {
		return "", &OpenProofError{Op: "rotate_key_generate", Err: err}
	}

	if oldKey, exists := ks.Keys[oldKeyID]; exists {
		oldKey.Status = "inactive"
		ks.Keys[oldKeyID] = oldKey

		keyData, err := ks.loadKey(oldKey.FilePath)
		if err != nil {
			return "", &OpenProofError{Op: "rotate_key_load_old", Err: err}
		}
		keyData.Status = "inactive"
		if err := ks.saveKey(*keyData); err != nil {
			return "", &OpenProofError{Op: "rotate_key_save_old", Err: err}
		}
	}

	ks.ActiveKeyID = newKeyID
	return newKeyID, nil
}
