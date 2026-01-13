package vc

import (
	"strconv"
)

// ZKIdentitySubject wraps IdentitySubject with ZK capabilities.
type ZKIdentitySubject struct {
	IdentitySubject
}

// ToFieldElements converts the identity subject to BBS+ messages.
func (s ZKIdentitySubject) ToFieldElements() ([][]byte, error) {
	return [][]byte{
		[]byte(s.ID),
		[]byte(s.GivenName),
		[]byte(s.FamilyName),
		[]byte(s.DateOfBirth),
		[]byte(s.Nationality),
		[]byte(s.DocumentType),
		[]byte(s.DocumentID),
		[]byte(s.PlaceOfBirth),
		[]byte(s.Gender),
		[]byte(s.Address),
		[]byte(s.VerifiedAt),
		[]byte(s.VerifiedLevel),
	}, nil
}

// FieldNames returns the ordered field names for the identity subject.
func (s ZKIdentitySubject) FieldNames() []string {
	return []string{
		"id",
		"givenName",
		"familyName",
		"dateOfBirth",
		"nationality",
		"documentType",
		"documentId",
		"placeOfBirth",
		"gender",
		"address",
		"verifiedAt",
		"verifiedLevel",
	}
}

// GetField returns a field value by name.
func (s ZKIdentitySubject) GetField(name string) (interface{}, bool) {
	switch name {
	case "id":
		return s.ID, true
	case "givenName":
		return s.GivenName, true
	case "familyName":
		return s.FamilyName, true
	case "dateOfBirth":
		return s.DateOfBirth, true
	case "nationality":
		return s.Nationality, true
	case "documentType":
		return s.DocumentType, true
	case "documentId":
		return s.DocumentID, true
	case "placeOfBirth":
		return s.PlaceOfBirth, true
	case "gender":
		return s.Gender, true
	case "address":
		return s.Address, true
	case "verifiedAt":
		return s.VerifiedAt, true
	case "verifiedLevel":
		return s.VerifiedLevel, true
	default:
		return nil, false
	}
}

// ZKEducationSubject wraps EducationSubject with ZK capabilities.
type ZKEducationSubject struct {
	EducationSubject
}

// ToFieldElements converts the education subject to BBS+ messages.
func (s ZKEducationSubject) ToFieldElements() ([][]byte, error) {
	return [][]byte{
		[]byte(s.ID),
		[]byte(s.InstitutionName),
		[]byte(s.InstitutionDID),
		[]byte(s.Degree),
		[]byte(s.FieldOfStudy),
		[]byte(s.GraduationDate),
		[]byte(s.CertificateName),
		[]byte(s.CourseName),
		[]byte(s.CompletionDate),
		[]byte(s.Grade),
		[]byte(strconv.Itoa(s.CreditsEarned)),
	}, nil
}

// FieldNames returns the ordered field names for the education subject.
func (s ZKEducationSubject) FieldNames() []string {
	return []string{
		"id",
		"institutionName",
		"institutionDid",
		"degree",
		"fieldOfStudy",
		"graduationDate",
		"certificateName",
		"courseName",
		"completionDate",
		"grade",
		"creditsEarned",
	}
}

// GetField returns a field value by name.
func (s ZKEducationSubject) GetField(name string) (interface{}, bool) {
	switch name {
	case "id":
		return s.ID, true
	case "institutionName":
		return s.InstitutionName, true
	case "institutionDid":
		return s.InstitutionDID, true
	case "degree":
		return s.Degree, true
	case "fieldOfStudy":
		return s.FieldOfStudy, true
	case "graduationDate":
		return s.GraduationDate, true
	case "certificateName":
		return s.CertificateName, true
	case "courseName":
		return s.CourseName, true
	case "completionDate":
		return s.CompletionDate, true
	case "grade":
		return s.Grade, true
	case "creditsEarned":
		return s.CreditsEarned, true
	default:
		return nil, false
	}
}

// ZKEmploymentSubject wraps EmploymentSubject with ZK capabilities.
type ZKEmploymentSubject struct {
	EmploymentSubject
}

// ToFieldElements converts the employment subject to BBS+ messages.
func (s ZKEmploymentSubject) ToFieldElements() ([][]byte, error) {
	currentEmployee := "false"
	if s.CurrentEmployee {
		currentEmployee = "true"
	}
	return [][]byte{
		[]byte(s.ID),
		[]byte(s.EmployerName),
		[]byte(s.EmployerDID),
		[]byte(s.JobTitle),
		[]byte(s.Department),
		[]byte(s.StartDate),
		[]byte(s.EndDate),
		[]byte(s.EmploymentType),
		[]byte(s.WorkLocation),
		[]byte(currentEmployee),
	}, nil
}

// FieldNames returns the ordered field names for the employment subject.
func (s ZKEmploymentSubject) FieldNames() []string {
	return []string{
		"id",
		"employerName",
		"employerDid",
		"jobTitle",
		"department",
		"startDate",
		"endDate",
		"employmentType",
		"workLocation",
		"currentEmployee",
	}
}

// GetField returns a field value by name.
func (s ZKEmploymentSubject) GetField(name string) (interface{}, bool) {
	switch name {
	case "id":
		return s.ID, true
	case "employerName":
		return s.EmployerName, true
	case "employerDid":
		return s.EmployerDID, true
	case "jobTitle":
		return s.JobTitle, true
	case "department":
		return s.Department, true
	case "startDate":
		return s.StartDate, true
	case "endDate":
		return s.EndDate, true
	case "employmentType":
		return s.EmploymentType, true
	case "workLocation":
		return s.WorkLocation, true
	case "currentEmployee":
		return s.CurrentEmployee, true
	default:
		return nil, false
	}
}

// ZKMembershipSubject wraps MembershipSubject with ZK capabilities.
type ZKMembershipSubject struct {
	MembershipSubject
}

// ToFieldElements converts the membership subject to BBS+ messages.
func (s ZKMembershipSubject) ToFieldElements() ([][]byte, error) {
	activeMember := "false"
	if s.ActiveMember {
		activeMember = "true"
	}
	// Join roles with comma for simple encoding
	rolesStr := ""
	for i, role := range s.Roles {
		if i > 0 {
			rolesStr += ","
		}
		rolesStr += role
	}
	return [][]byte{
		[]byte(s.ID),
		[]byte(s.OrganizationName),
		[]byte(s.OrganizationDID),
		[]byte(s.MembershipID),
		[]byte(s.MembershipType),
		[]byte(s.Role),
		[]byte(rolesStr),
		[]byte(s.AccessLevel),
		[]byte(s.StartDate),
		[]byte(s.ExpirationDate),
		[]byte(activeMember),
	}, nil
}

// FieldNames returns the ordered field names for the membership subject.
func (s ZKMembershipSubject) FieldNames() []string {
	return []string{
		"id",
		"organizationName",
		"organizationDid",
		"membershipId",
		"membershipType",
		"role",
		"roles",
		"accessLevel",
		"startDate",
		"expirationDate",
		"activeMember",
	}
}

// GetField returns a field value by name.
func (s ZKMembershipSubject) GetField(name string) (interface{}, bool) {
	switch name {
	case "id":
		return s.ID, true
	case "organizationName":
		return s.OrganizationName, true
	case "organizationDid":
		return s.OrganizationDID, true
	case "membershipId":
		return s.MembershipID, true
	case "membershipType":
		return s.MembershipType, true
	case "role":
		return s.Role, true
	case "roles":
		return s.Roles, true
	case "accessLevel":
		return s.AccessLevel, true
	case "startDate":
		return s.StartDate, true
	case "expirationDate":
		return s.ExpirationDate, true
	case "activeMember":
		return s.ActiveMember, true
	default:
		return nil, false
	}
}
