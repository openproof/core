package core

import "fmt"

// OpenProofError represents all errors in the OpenProof system
type OpenProofError struct {
	Op  string // Operation being performed
	Err error  // Underlying error
}

func (e *OpenProofError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return e.Op
}

func (e *OpenProofError) Unwrap() error {
	return e.Err
}
