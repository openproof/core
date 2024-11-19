package core

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Version of the OpenProof protocol
const ProtocolVersion = "1.0.0"

// Record represents a single AI interaction with its proof
type Record struct {
	Version     string                 `json:"version"`
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Interaction Interaction            `json:"interaction"`
	Proof       Proof                  `json:"proof"`
	Access      AccessControl          `json:"access"`
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
	sync.RWMutex
}

// AccessControlChange logs changes to access control
type AccessControlChange struct {
	Timestamp   time.Time `json:"timestamp"`
	ChangedBy   string    `json:"changed_by"`
	Description string    `json:"description"`
}

// NewRecord creates a new record with generated ID and timestamp
func NewRecord(interaction Interaction, access AccessControl) *Record {
	return &Record{
		Version:     ProtocolVersion,
		ID:          generateID("record"),
		Timestamp:   time.Now(),
		Interaction: interaction,
		Access:      access,
		Tags:        make([]string, 0),
		Extension:   make(map[string]interface{}),
	}
}

// ValidateRecord performs validation on the record fields
func (r *Record) ValidateRecord() error {
	if r.ID == "" {
		return errors.New("record ID cannot be empty")
	}
	if r.Version == "" {
		return errors.New("record version must be set")
	}
	if r.Timestamp.IsZero() {
		return errors.New("timestamp must be set")
	}
	if r.Proof.Hash == "" || r.Proof.Signature == "" {
		return errors.New("proof hash and signature are required")
	}
	if r.Proof.HashAlgorithm == "" || r.Proof.SignatureAlgorithm == "" {
		return errors.New("hash and signature algorithms must be specified")
	}
	if err := r.validateHashChain(); err != nil {
		return fmt.Errorf("hash chain validation failed: %w", err)
	}
	if len(r.Interaction.Input.Data) > MaxContentSize || len(r.Interaction.Output.Data) > MaxContentSize {
		return fmt.Errorf("content data exceeds maximum allowed size of %d bytes", MaxContentSize)
	}
	return nil
}

// validateHashChain checks the integrity of the hash chain
func (r *Record) validateHashChain() error {
	if r.Proof.PreviousHash == "" && r.Proof.PreviousID != "" {
		return errors.New("previous hash must be set if previous ID is provided")
	}
	// TODO: Implement retrieval and verification of previous record
	return nil
}

// GenerateHash computes the SHA256 hash of the record
func (r *Record) GenerateHash() string {
	data, _ := json.Marshal(r)
	hash := sha256.Sum256(data)
	return encodeBase64(hash[:])
}

// AuditAccessControlChange records a change to the access control settings
func (ac *AccessControl) AuditAccessControlChange(changedBy, description string) {
	ac.Lock()
	defer ac.Unlock()

	change := AccessControlChange{
		Timestamp:   time.Now(),
		ChangedBy:   changedBy,
		Description: description,
	}
	ac.AuditLog = append(ac.AuditLog, change)
}

// SetProof sets the proof data for the record
func (r *Record) SetProof(keyID string) {
	r.Proof = Proof{
		Hash:               r.GenerateHash(),
		KeyID:              keyID,
		SignedAt:           time.Now(),
		HashAlgorithm:      HashAlgorithmSHA256,
		SignatureAlgorithm: SignatureAlgorithmECDSA,
	}
}
