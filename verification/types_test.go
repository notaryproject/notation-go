package verification

import (
	"strconv"
	"testing"
)

func TestFindVerificationLevel(t *testing.T) {
	tests := []struct {
		verificationLevel   string
		wantErr             bool
		verificationActions []VerificationAction
	}{
		{"strict", false, []VerificationAction{Enforced, Enforced, Enforced, Enforced, Enforced}},
		{"permissive", false, []VerificationAction{Enforced, Enforced, Logged, Logged, Logged}},
		{"audit", false, []VerificationAction{Enforced, Logged, Logged, Logged, Logged}},
		{"skip", false, []VerificationAction{Skipped, Skipped, Skipped, Skipped, Skipped}},
		{"invalid", true, []VerificationAction{}},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {

			level, err := FindVerificationLevel(tt.verificationLevel)

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
