package verification

import (
	"strconv"
	"testing"
)

func TestGetVerificationLevel(t *testing.T) {
	tests := []struct {
		verificationLevel   SignatureVerification
		wantErr             bool
		verificationActions []VerificationAction
	}{
		{SignatureVerification{Level: "strict"}, false, []VerificationAction{Enforced, Enforced, Enforced, Enforced, Enforced}},
		{SignatureVerification{Level: "permissive"}, false, []VerificationAction{Enforced, Enforced, Logged, Logged, Logged}},
		{SignatureVerification{Level: "audit"}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{SignatureVerification{Level: "skip"}, false, []VerificationAction{Skipped, Skipped, Skipped, Skipped, Skipped}},
		{SignatureVerification{Level: "invalid"}, true, []VerificationAction{}},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {

			level, err := GetVerificationLevel(tt.verificationLevel)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestFindVerificationLevel Error: %q WantErr: %v", err, tt.wantErr)
			} else {
				for index, action := range tt.verificationActions {
					if action != level.VerificationMap[VerificationTypes[index]] {
						t.Errorf("%q verification action should be %q for Verification Level %q", VerificationTypes[index], action, tt.verificationLevel)
					}
				}
			}
		})
	}
}

func TestCustomVerificationLevel(t *testing.T) {
	tests := []struct {
		customVerification  SignatureVerification
		wantErr             bool
		verificationActions []VerificationAction
	}{
		{SignatureVerification{Level: "strict", Override: map[string]string{"integrity": "log"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"authenticity": "skip"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"authenticTimestamp": "skip"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"expiry": "skip"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "skip", Override: map[string]string{"authenticity": "log"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "invalid", Override: map[string]string{"authenticity": "log"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"invalid": "log"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"authenticity": "invalid"}}, true, []VerificationAction{}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"authenticity": "log"}}, false, []VerificationAction{Enforced, Logged, Enforced, Enforced, Enforced}},
		{SignatureVerification{Level: "permissive", Override: map[string]string{"authenticity": "log"}}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{SignatureVerification{Level: "audit", Override: map[string]string{"authenticity": "log"}}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"expiry": "log"}}, false, []VerificationAction{Enforced, Enforced, Enforced, Logged, Enforced}},
		{SignatureVerification{Level: "permissive", Override: map[string]string{"expiry": "log"}}, false, []VerificationAction{Enforced, Enforced, Logged, Logged, Logged}},
		{SignatureVerification{Level: "audit", Override: map[string]string{"expiry": "log"}}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"revocation": "log"}}, false, []VerificationAction{Enforced, Enforced, Enforced, Enforced, Logged}},
		{SignatureVerification{Level: "permissive", Override: map[string]string{"revocation": "log"}}, false, []VerificationAction{Enforced, Enforced, Logged, Logged, Logged}},
		{SignatureVerification{Level: "audit", Override: map[string]string{"revocation": "log"}}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"revocation": "skip"}}, false, []VerificationAction{Enforced, Enforced, Enforced, Enforced, Skipped}},
		{SignatureVerification{Level: "permissive", Override: map[string]string{"revocation": "skip"}}, false, []VerificationAction{Enforced, Enforced, Logged, Logged, Skipped}},
		{SignatureVerification{Level: "audit", Override: map[string]string{"revocation": "skip"}}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Skipped}},
		{SignatureVerification{Level: "permissive", Override: map[string]string{"authenticTimestamp": "log"}}, false, []VerificationAction{Enforced, Enforced, Logged, Logged, Logged}},
		{SignatureVerification{Level: "audit", Override: map[string]string{"authenticTimestamp": "log"}}, false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{SignatureVerification{Level: "strict", Override: map[string]string{"authenticTimestamp": "log"}}, false, []VerificationAction{Enforced, Enforced, Logged, Enforced, Enforced}},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			level, err := GetVerificationLevel(tt.customVerification)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestCustomVerificationLevel Error: %q WantErr: %v", err, tt.wantErr)
			} else {
				if !tt.wantErr && len(tt.verificationActions) == 0 {
					t.Errorf("test case isn't configured with VerificationActions")
				}
				for index, action := range tt.verificationActions {
					if action != level.VerificationMap[VerificationTypes[index]] {
						t.Errorf("%q verification action should be %q for custom verification %q", VerificationTypes[index], action, tt.customVerification)
					}
				}
			}
		})
	}
}
