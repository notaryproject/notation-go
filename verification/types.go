package verification

import (
	"fmt"
	nsigner "github.com/notaryproject/notation-core-go/signer"
)

// VerificationType is an enum for signature verification types such as Integrity, Authenticity, etc.
type VerificationType string

// VerificationAction is an enum for signature verification actions such as Enforced, Logged, Skipped.
type VerificationAction string

// VerificationResult encapsulates the verification result (passed or failed) for a verification type, including the
// desired verification action as specified in the trust policy
type VerificationResult struct {
	// Success is set to true if the verification was successful
	Success bool
	// Type of verification that is performed
	Type VerificationType
	// Action is the intended action for the given verification type as defined in the trust policy
	Action VerificationAction
	// Err is set if there are any errors during the verification process
	Error error
}

// SignatureVerificationOutcome encapsulates the SignerInfo (that includes the details of the digital signature)
// and results for each verification type that was performed
type SignatureVerificationOutcome struct {
	// SignerInfo contains the details of the digital signature and associated metadata
	SignerInfo *nsigner.SignerInfo
	// VerificationLevel describes what verification level was used for performing signature verification
	VerificationLevel *VerificationLevel
	// VerificationResults contains the verifications performed on the signature and their results
	VerificationResults []*VerificationResult
	// SignedAnnotations contains arbitrary metadata relating to the target artifact that was signed
	SignedAnnotations map[string]string
	// Error that caused the verification to fail (if it fails)
	Error error
}

// VerificationLevel encapsulates the signature verification preset and it's actions for each verification type
type VerificationLevel struct {
	Name            string
	VerificationMap map[VerificationType]VerificationAction
}

const (
	Integrity          VerificationType = "Integrity"
	Authenticity       VerificationType = "Authenticity"
	AuthenticTimestamp VerificationType = "AuthenticTimestamp"
	Expiry             VerificationType = "Expiry"
	Revocation         VerificationType = "Revocation"

	Enforced VerificationAction = "Enforced"
	Logged   VerificationAction = "Logged"
	Skipped  VerificationAction = "Skipped"
)

var (
	Strict = &VerificationLevel{
		"strict",
		map[VerificationType]VerificationAction{
			Integrity:          Enforced,
			Authenticity:       Enforced,
			AuthenticTimestamp: Enforced,
			Expiry:             Enforced,
			Revocation:         Enforced,
		},
	}

	Permissive = &VerificationLevel{
		"permissive",
		map[VerificationType]VerificationAction{
			Integrity:          Enforced,
			Authenticity:       Enforced,
			AuthenticTimestamp: Logged,
			Expiry:             Logged,
			Revocation:         Logged,
		},
	}

	Audit = &VerificationLevel{
		"audit",
		map[VerificationType]VerificationAction{
			Integrity:          Enforced,
			Authenticity:       Logged,
			AuthenticTimestamp: Logged,
			Expiry:             Logged,
			Revocation:         Logged,
		},
	}

	Skip = &VerificationLevel{
		"skip",
		map[VerificationType]VerificationAction{
			Integrity:          Skipped,
			Authenticity:       Skipped,
			AuthenticTimestamp: Skipped,
			Expiry:             Skipped,
			Revocation:         Skipped,
		},
	}

	VerificationTypes = []VerificationType{
		Integrity,
		Authenticity,
		AuthenticTimestamp,
		Expiry,
		Revocation,
	}

	VerificationActions = []VerificationAction{
		Enforced,
		Logged,
		Skipped,
	}

	VerificationLevels = []*VerificationLevel{
		Strict,
		Permissive,
		Audit,
		Skip,
	}
)

// FindVerificationLevel finds if the given string corresponds to a supported VerificationLevel, otherwise throws an error
func FindVerificationLevel(s string) (*VerificationLevel, error) {

	for _, level := range VerificationLevels {
		if level.Name == s {
			return level, nil
		}
	}
	return nil, fmt.Errorf("invalid signature verification level %q", s)
}
