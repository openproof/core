// record.go
package core

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Record represents a single AI interaction with its proof
type Record struct {
	Version     string                 `json:"version"`
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Interaction Interaction            `json:"interaction"`
	Proof       Proof                  `json:"proof"`
	Access      *AccessControl         `json:"access"`
	Tags        []string               `json:"tags,omitempty"`
	Extension   map[string]interface{} `json:"extension,omitempty"`
}

// Interaction contains the actual AI interaction details
type Interaction struct {
	System     System  `json:"system"`
	Type       string  `json:"type"`
	Input      Content `json:"input"`
	Output     Content `json:"output"`
	WorkflowID string  `json:"workflow_id,omitempty"`
	StepID     string  `json:"step_id,omitempty"`
}

// System identifies the AI system used
type System struct {
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	Version       string `json:"version,omitempty"`
	Environment   string `json:"environment,omitempty"`
	CaptureMethod string `json:"capture_method,omitempty"`
}

// Proof contains verification data
type Proof struct {
	Hash               string    `json:"hash"`
	Signature          string    `json:"signature"`
	PreviousHash       string    `json:"previous_hash"`
	PreviousID         string    `json:"previous_id"`
	KeyID              string    `json:"key_id"`
	SignedAt           time.Time `json:"signed_at"`
	HashAlgorithm      string    `json:"hash_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
}

// AccessControl defines who can access records
type AccessControl struct {
	Owner      string                `json:"owner"`
	Team       string                `json:"team"`
	Level      string                `json:"level"`
	SharedWith []string              `json:"shared_with,omitempty"`
	Roles      []string              `json:"roles,omitempty"`
	AuditLog   []AccessControlChange `json:"audit_log,omitempty"`
	mu         sync.RWMutex
}

// AccessControlChange logs changes to access control
type AccessControlChange struct {
	Timestamp   time.Time `json:"timestamp"`
	ChangedBy   string    `json:"changed_by"`
	Description string    `json:"description"`
}

// RecordManager handles record operations with configuration
type RecordManager struct {
	config *Config
}

// NewRecordManager creates a new record manager with configuration
func NewRecordManager(config *Config) *RecordManager {
	return &RecordManager{
		config: config,
	}
}

// NewRecord creates a new record with generated ID and timestamp
func (rm *RecordManager) NewRecord(interaction Interaction, access *AccessControl) *Record { // Changed parameter to pointer
	if access == nil {
		access = &AccessControl{} // Ensure we never have a nil pointer
	}

	// Set system details from config
	interaction.System.Environment = rm.config.Environment
	interaction.System.Provider = rm.config.Provider
	interaction.System.CaptureMethod = rm.config.CaptureMethod

	return &Record{
		Version:     "1.0.0",
		ID:          generateID("record"),
		Timestamp:   time.Now(),
		Interaction: interaction,
		Access:      access, // Now safely copying a pointer
		Tags:        make([]string, 0),
		Extension:   make(map[string]interface{}),
	}
}

// ValidateRecord performs validation on the record fields
func (rm *RecordManager) ValidateRecord(record *Record) error {
	var errors []string

	if record.ID == "" {
		errors = append(errors, "record ID cannot be empty")
	}
	if record.Version == "" {
		errors = append(errors, "record version must be set")
	}
	if record.Timestamp.IsZero() {
		errors = append(errors, "timestamp must be set")
	}
	if record.Proof.Hash == "" || record.Proof.Signature == "" {
		errors = append(errors, "proof hash and signature are required")
	}
	if record.Proof.HashAlgorithm != rm.config.HashAlgorithm {
		errors = append(errors, fmt.Sprintf("invalid hash algorithm: %s", record.Proof.HashAlgorithm))
	}
	if record.Proof.SignatureAlgorithm != rm.config.SignatureAlgorithm {
		errors = append(errors, fmt.Sprintf("invalid signature algorithm: %s", record.Proof.SignatureAlgorithm))
	}

	// Validate content size
	if len(record.Interaction.Input.Data) > int(rm.config.MaxContentSize) {
		errors = append(errors, fmt.Sprintf("input content exceeds maximum size of %d bytes", rm.config.MaxContentSize))
	}
	if len(record.Interaction.Output.Data) > int(rm.config.MaxContentSize) {
		errors = append(errors, fmt.Sprintf("output content exceeds maximum size of %d bytes", rm.config.MaxContentSize))
	}

	if err := rm.validateHashChain(record); err != nil {
		errors = append(errors, fmt.Sprintf("hash chain validation failed: %v", err))
	}

	if len(errors) > 0 {
		return &OpenProofError{
			Op:  "validate_record",
			Err: fmt.Errorf("validation errors: %v", errors),
		}
	}

	return nil
}

// validateHashChain checks the integrity of the hash chain
func (rm *RecordManager) validateHashChain(record *Record) error {
	if record.Proof.PreviousHash == "" && record.Proof.PreviousID != "" {
		return &OpenProofError{
			Op:  "validate_hash_chain",
			Err: errors.New("previous hash must be set if previous ID is provided"),
		}
	}
	// TODO: Implement retrieval and verification of previous record
	return nil
}

// GenerateHash computes the hash of the record using configured algorithm
func (rm *RecordManager) GenerateHash(record *Record) string {
	// Currently only supports SHA256, but could be extended based on config
	if rm.config.HashAlgorithm != DefaultHashAlgorithm {
		// Log a warning or handle unsupported algorithms
		// For now, fallback to SHA256
	}

	data, _ := json.Marshal(record)
	hash := sha256.Sum256(data)
	return encodeBase64(hash[:])
}

// SetProof sets the proof data for the record
func (rm *RecordManager) SetProof(record *Record, keyID string) {
	record.Proof = Proof{
		Hash:               rm.GenerateHash(record),
		KeyID:              keyID,
		SignedAt:           time.Now(),
		HashAlgorithm:      rm.config.HashAlgorithm,
		SignatureAlgorithm: rm.config.SignatureAlgorithm,
	}
}

// AuditAccessControlChange records a change to the access control settings
func (ac *AccessControl) AuditAccessControlChange(changedBy, description string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	change := AccessControlChange{
		Timestamp:   time.Now(),
		ChangedBy:   changedBy,
		Description: description,
	}
	ac.AuditLog = append(ac.AuditLog, change)
}

// GetOwner returns the owner with proper locking
func (ac *AccessControl) GetOwner() string {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.Owner
}

// SetOwner sets the owner with proper locking
func (ac *AccessControl) SetOwner(owner string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.Owner = owner
}
