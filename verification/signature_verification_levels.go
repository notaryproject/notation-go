package verification

import "fmt"

// VerificationType is an enum for signature verification types such as Integrity, Authenticity, etc.
type VerificationType string

// VerificationAction is an enum for signature verification actions such as Enforced, Logged, Skipped.
type VerificationAction string

// SignatureVerificationLevel encapsulates the signature verification preset and it's actions for each verification type
type SignatureVerificationLevel struct {
	Name            string
	VerificationMap map[VerificationType]VerificationAction
}

const (
	Integrity             VerificationType = "Integrity"
	Authenticity          VerificationType = "Authenticity"
	TrustedTimestampCheck VerificationType = "TrustedTimestampCheck"
	ExpiryCheck           VerificationType = "ExpiryCheck"
	RevocationCheck       VerificationType = "RevocationCheck"

	Enforced VerificationAction = "Enforced"
	Logged   VerificationAction = "Logged"
	Skipped  VerificationAction = "Skipped"
)

var (
	Strict = SignatureVerificationLevel{
		"strict",
		map[VerificationType]VerificationAction{
			Integrity:             Enforced,
			Authenticity:          Enforced,
			TrustedTimestampCheck: Enforced,
			ExpiryCheck:           Enforced,
			RevocationCheck:       Enforced,
		},
	}

	Permissive = SignatureVerificationLevel{
		"permissive",
		map[VerificationType]VerificationAction{
			Integrity:             Enforced,
			Authenticity:          Enforced,
			TrustedTimestampCheck: Logged,
			ExpiryCheck:           Logged,
			RevocationCheck:       Logged,
		},
	}

	Audit = SignatureVerificationLevel{
		"audit",
		map[VerificationType]VerificationAction{
			Integrity:             Enforced,
			Authenticity:          Logged,
			TrustedTimestampCheck: Logged,
			ExpiryCheck:           Logged,
			RevocationCheck:       Logged,
		},
	}

	Skip = SignatureVerificationLevel{
		"skip",
		map[VerificationType]VerificationAction{
			Integrity:             Skipped,
			Authenticity:          Skipped,
			TrustedTimestampCheck: Skipped,
			ExpiryCheck:           Skipped,
			RevocationCheck:       Skipped,
		},
	}

	VerificationTypes = []VerificationType{
		Integrity,
		Authenticity,
		TrustedTimestampCheck,
		ExpiryCheck,
		RevocationCheck,
	}

	VerificationActions = []VerificationAction{
		Enforced,
		Logged,
		Skipped,
	}

	SignatureVerificationLevels = []SignatureVerificationLevel{
		Strict,
		Permissive,
		Audit,
		Skip,
	}
)

// FindSignatureVerificationLevel finds if the given string corresponds to a supported SignatureVerificationLevel, otherwise throws an error
func FindSignatureVerificationLevel(s string) (*SignatureVerificationLevel, error) {

	for _, level := range SignatureVerificationLevels {
		if level.Name == s {
			return &level, nil
		}
	}
	return nil, fmt.Errorf("invalid SignatureVerification %q", s)
}
