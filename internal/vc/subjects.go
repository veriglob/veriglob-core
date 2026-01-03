package vc

// Credential type constants
const (
	CredentialTypeIdentity   = "IdentityCredential"
	CredentialTypeEducation  = "EducationCredential"
	CredentialTypeEmployment = "EmploymentCredential"
	CredentialTypeMembership = "MembershipCredential"
)

// CredentialSubject is the interface all credential subjects must implement
type CredentialSubject interface {
	GetID() string
	CredentialType() string
}

// IdentitySubject represents KYC/identity verification credentials
type IdentitySubject struct {
	ID            string `json:"id"`
	GivenName     string `json:"givenName"`
	FamilyName    string `json:"familyName"`
	DateOfBirth   string `json:"dateOfBirth"`
	Nationality   string `json:"nationality,omitempty"`
	DocumentType  string `json:"documentType,omitempty"`
	DocumentID    string `json:"documentId,omitempty"`
	PlaceOfBirth  string `json:"placeOfBirth,omitempty"`
	Gender        string `json:"gender,omitempty"`
	Address       string `json:"address,omitempty"`
	VerifiedAt    string `json:"verifiedAt,omitempty"`
	VerifiedLevel string `json:"verifiedLevel,omitempty"`
}

func (s IdentitySubject) GetID() string          { return s.ID }
func (s IdentitySubject) CredentialType() string { return CredentialTypeIdentity }

// EducationSubject represents educational credentials
type EducationSubject struct {
	ID              string `json:"id"`
	InstitutionName string `json:"institutionName"`
	InstitutionDID  string `json:"institutionDid,omitempty"`
	Degree          string `json:"degree,omitempty"`
	FieldOfStudy    string `json:"fieldOfStudy,omitempty"`
	GraduationDate  string `json:"graduationDate,omitempty"`
	CertificateName string `json:"certificateName,omitempty"`
	CourseName      string `json:"courseName,omitempty"`
	CompletionDate  string `json:"completionDate,omitempty"`
	Grade           string `json:"grade,omitempty"`
	CreditsEarned   int    `json:"creditsEarned,omitempty"`
}

func (s EducationSubject) GetID() string          { return s.ID }
func (s EducationSubject) CredentialType() string { return CredentialTypeEducation }

// EmploymentSubject represents employment credentials
type EmploymentSubject struct {
	ID              string `json:"id"`
	EmployerName    string `json:"employerName"`
	EmployerDID     string `json:"employerDid,omitempty"`
	JobTitle        string `json:"jobTitle"`
	Department      string `json:"department,omitempty"`
	StartDate       string `json:"startDate"`
	EndDate         string `json:"endDate,omitempty"`
	EmploymentType  string `json:"employmentType,omitempty"`
	WorkLocation    string `json:"workLocation,omitempty"`
	CurrentEmployee bool   `json:"currentEmployee"`
}

func (s EmploymentSubject) GetID() string          { return s.ID }
func (s EmploymentSubject) CredentialType() string { return CredentialTypeEmployment }

// MembershipSubject represents organization membership credentials
type MembershipSubject struct {
	ID               string   `json:"id"`
	OrganizationName string   `json:"organizationName"`
	OrganizationDID  string   `json:"organizationDid,omitempty"`
	MembershipID     string   `json:"membershipId,omitempty"`
	MembershipType   string   `json:"membershipType,omitempty"`
	Role             string   `json:"role,omitempty"`
	Roles            []string `json:"roles,omitempty"`
	AccessLevel      string   `json:"accessLevel,omitempty"`
	StartDate        string   `json:"startDate"`
	ExpirationDate   string   `json:"expirationDate,omitempty"`
	ActiveMember     bool     `json:"activeMember"`
}

func (s MembershipSubject) GetID() string          { return s.ID }
func (s MembershipSubject) CredentialType() string { return CredentialTypeMembership }
