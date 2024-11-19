# core
# OpenProof

OpenProof is a Go library that provides cryptographic proof and verification capabilities for AI interactions. It enables secure recording, encryption, and verification of AI system inputs and outputs with features like content encryption, key management, and access control.

## Features

- 🔐 Secure key management with automatic rotation
- 🔒 AES-256-GCM encryption for content
- 📦 Content compression (GZIP)
- ⛓️ Hash chain verification
- 🔍 Access control with audit logging
- 📝 Complete interaction records
- 🚀 Easy-to-use API

## Installation

```bash
go get github.com/openproof/core
```

## Quick Start

```go
package main

import (
    "log"
    "github.com/openproof/core"
)

func main() {
    // Initialize key store
    keyStore, err := core.NewKeyStore("/var/lib/openproof/keys")
    if err != nil {
        log.Fatal(err)
    }

    // Create content processor
    processor := core.NewContentProcessor(keyStore)

    // Create an interaction record
    interaction := core.Interaction{
        System: core.System{
            Provider: core.ProviderOpenAI,
            Model:    "gpt-4",
            Environment: core.EnvironmentAPI,
        },
        Type: "chat",
        Input: core.Content{
            Type: core.ContentTypeText,
            Data: "What is the meaning of life?",
        },
        Output: core.Content{
            Type: core.ContentTypeText,
            Data: "42",
        },
    }

    // Set access control
    access := core.AccessControl{
        Owner: "user123",
        Level: core.VisibilityPrivate,
    }

    // Create and process record
    record := core.NewRecord(interaction, access)

    // Encrypt and compress content
    if err := processor.ProcessContent(&record.Interaction.Input); err != nil {
        log.Fatal(err)
    }
    if err := processor.ProcessContent(&record.Interaction.Output); err != nil {
        log.Fatal(err)
    }

    // Set proof
    record.SetProof(keyStore.ActiveKeyID)

    // Validate record
    if err := record.ValidateRecord(); err != nil {
        log.Fatal(err)
    }
}
```

## Key Components

### Record
The `Record` type represents a complete AI interaction with proof:
```go
type Record struct {
    Version     string
    ID          string
    Timestamp   time.Time
    Interaction Interaction
    Proof       Proof
    Access      AccessControl
    Tags        []string
    Extension   map[string]interface{}
}
```

### Content Processing
Secure your content with encryption and compression:
```go
processor := core.NewContentProcessor(keyStore)
err := processor.ProcessContent(&content)
```

### Key Management
Manage encryption keys with automatic rotation:
```go
keyStore, err := core.NewKeyStore("/path/to/keys")
newKeyID, err := keyStore.RotateKey()
```

### Access Control
Control and audit access to records:
```go
access := core.AccessControl{
    Owner: "user123",
    Team: "engineering",
    Level: core.VisibilityPrivate,
    Roles: []string{"admin", "user"},
}
```

## Security Features

- AES-256-GCM encryption for all sensitive content
- Secure key storage with proper file permissions
- Hash chain verification for record integrity
- Audit logging for access control changes
- Content compression for efficient storage
- Rate limiting capabilities

## Best Practices

1. **Key Management**
   - Rotate keys regularly (monthly recommended)
   - Secure key storage location with proper permissions
   - Back up keys in a secure location

2. **Content Processing**
   - Always process sensitive content before storage
   - Validate records after processing
   - Handle encryption errors appropriately

3. **Access Control**
   - Set appropriate visibility levels
   - Use audit logging for sensitive operations
   - Implement proper role-based access

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Security

For security concerns, please email security@openproof.dev instead of using the issue tracker.

## Project Status

OpenProof is in active development. While the core functionality is stable, the API may change as we add new features and improvements.

