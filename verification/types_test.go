package verification

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestGetVerificationLevel(t *testing.T) {
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
		customVerification  string
		wantErr             bool
		verificationActions []VerificationAction
	}{
		{"{\"level\":\"strict\",\"override\":{\"integrity\":\"log\"}}", true, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"authenticity\":\"skip\"}}", true, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"authenticTimestamp\":\"skip\"}}", true, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"expiry\":\"skip\"}}", true, []VerificationAction{}},
		{"{\"level\":\"skip\",\"override\":{\"authenticity\":\"log\"}}", true, []VerificationAction{}},
		{"{\"level\":\"invalid\",\"override\":{\"authenticity\":\"log\"}}", true, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"invalid\":\"log\"}}", true, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"authenticity\":\"invalid\"}}", true, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"authenticity\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"permissive\",\"override\":{\"authenticity\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"audit\",\"override\":{\"authenticity\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"expiry\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"permissive\",\"override\":{\"expiry\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"audit\",\"override\":{\"expiry\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"revocation\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"permissive\",\"override\":{\"revocation\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"audit\",\"override\":{\"revocation\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"revocation\":\"skip\"}}", false, []VerificationAction{}},
		{"{\"level\":\"permissive\",\"override\":{\"authenticTimestamp\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"audit\",\"override\":{\"authenticTimestamp\":\"log\"}}", false, []VerificationAction{}},
		{"{\"level\":\"strict\",\"override\":{\"authenticTimestamp\":\"log\"}}", false, []VerificationAction{}},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var customVerification interface{}
			err := json.Unmarshal([]byte(tt.customVerification), &customVerification)
			if err != nil {
				t.Fatalf("TestCustomVerificationLevel json parsing error :%q", err)
			}

			level, err := GetVerificationLevel(customVerification)

			if tt.wantErr != (err != nil) {
				t.Fatalf("TestCustomVerificationLevel Error: %q WantErr: %v", err, tt.wantErr)
			} else {
				for index, action := range tt.verificationActions {
					if action != level.VerificationMap[VerificationTypes[index]] {
						t.Errorf("%q verification action should be %q for custom verification %q", VerificationTypes[index], action, tt.customVerification)
					}
				}
			}
		})
	}
}
