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
	Path        string
	Permissions os.FileMode
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
	FilePath  string    `json:"-"`
}

// KeyData represents the actual key material and metadata
type KeyData struct {
	KeyMetadata
	Material []byte `json:"-"` // Raw key material, not serialized to JSON
}

// NewKeyStore initializes a new key store
func NewKeyStore(path string) (*KeyStore, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, &OpenProofError{Op: "create_keystore", Err: err}
	}

	ks := &KeyStore{
		Path:        path, // needs a config
		Permissions: DefaultKeyPermissions,
		Keys:        make(map[string]KeyMetadata),
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
			// Update key file
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
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Status:    "active",
		FilePath:  filepath.Join(ks.Path, fmt.Sprintf("%s.key", keyID)),
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

// GetActiveKey returns the currently active encryption key
func (ks *KeyStore) GetActiveKey() ([]byte, error) {
	ks.RLock()
	defer ks.RUnlock()

	if ks.ActiveKeyID == "" {
		return nil, &OpenProofError{Op: "get_active_key", Err: fmt.Errorf("no active key")}
	}

	keyData, err := ks.loadKey(filepath.Join(ks.Path, fmt.Sprintf("%s.key", ks.ActiveKeyID)))
	if err != nil {
		return nil, err
	}

	return keyData.Material, nil
}

// saveKey saves a key to disk
func (ks *KeyStore) saveKey(keyData KeyData) error {
	file, err := os.OpenFile(keyData.FilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ks.Permissions)
	if err != nil {
		return &OpenProofError{Op: "create_key_file", Err: err}
	}
	defer file.Close()

	// Create storage structure
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

// loadKey loads a key from disk
func (ks *KeyStore) loadKey(path string) (*KeyData, error) {
	file, err := os.Open(path) // Use os.Open for read-only
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

	// Set FilePath after loading
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

	files, err := os.ReadDir(ks.Path)
	if err != nil {
		return &OpenProofError{Op: "read_keystore", Err: err}
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".key" {
			continue
		}

		keyData, err := ks.loadKey(filepath.Join(ks.Path, file.Name()))
		if err != nil {
			return err
		}

		ks.Keys[keyData.ID] = keyData.KeyMetadata
		if keyData.Status == "active" {
			ks.ActiveKeyID = keyData.ID
		}
	}

	return nil
}

// RotateKey creates a new key and marks the old one as inactive
func (ks *KeyStore) RotateKey() (string, error) {
	ks.Lock()
	defer ks.Unlock()

	oldKeyID := ks.ActiveKeyID

	// Generate new key
	newKeyID, err := ks.GenerateKey()
	if err != nil {
		return "", &OpenProofError{Op: "rotate_key_generate", Err: err}
	}

	// Update old key status
	if oldKey, exists := ks.Keys[oldKeyID]; exists {
		oldKey.Status = "inactive"
		ks.Keys[oldKeyID] = oldKey

		// Update key file
		keyData, err := ks.loadKey(oldKey.FilePath)
		if err != nil {
			return "", &OpenProofError{Op: "rotate_key_load_old", Err: err}
		}
		keyData.Status = "inactive"
		if err := ks.saveKey(*keyData); err != nil {
			return "", &OpenProofError{Op: "rotate_key_save_old", Err: err}
		}
	}
	// Set new key as active
	ks.ActiveKeyID = newKeyID

	return newKeyID, nil
}
