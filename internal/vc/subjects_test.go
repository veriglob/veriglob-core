package vc

import (
	"testing"
)

func TestCredentialSubjects(t *testing.T) {
	tests := []struct {
		name         string
		subject      CredentialSubject
		expectedType string
		expectedID   string
	}{
		{
			name: "IdentitySubject",
			subject: IdentitySubject{
				ID: "did:example:123",
			},
			expectedType: CredentialTypeIdentity,
			expectedID:   "did:example:123",
		},
		{
			name: "EducationSubject",
			subject: EducationSubject{
				ID: "did:example:456",
			},
			expectedType: CredentialTypeEducation,
			expectedID:   "did:example:456",
		},
		{
			name: "EmploymentSubject",
			subject: EmploymentSubject{
				ID: "did:example:789",
			},
			expectedType: CredentialTypeEmployment,
			expectedID:   "did:example:789",
		},
		{
			name: "MembershipSubject",
			subject: MembershipSubject{
				ID: "did:example:abc",
			},
			expectedType: CredentialTypeMembership,
			expectedID:   "did:example:abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.subject.CredentialType(); got != tt.expectedType {
				t.Errorf("CredentialType() = %v, want %v", got, tt.expectedType)
			}
			if got := tt.subject.GetID(); got != tt.expectedID {
				t.Errorf("GetID() = %v, want %v", got, tt.expectedID)
			}
		})
	}
}
