package verification

import "fmt"

// VerificationType is an enum for signature verification types such as Integrity, Authenticity, etc.
type VerificationType string

// VerificationAction is an enum for signature verification actions such as Enforced, Logged, Skipped.
type VerificationAction string

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
