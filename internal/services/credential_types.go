package services

// CredentialTypeInfo represents information about a credential type
type CredentialTypeInfo struct {
	Type         string   `json:"type"`
	DisplayName  string   `json:"display_name"`
	Description  string   `json:"description"`
	Category     string   `json:"category"`
	CommonClaims []string `json:"common_claims"`
}

// CredentialCategory represents a category of credentials
type CredentialCategory struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

// CredentialTypesResponse represents the response for credential types
type CredentialTypesResponse struct {
	CredentialTypes []CredentialTypeInfo `json:"credential_types"`
	Categories      []CredentialCategory `json:"categories"`
}

// GetCredentialCategories returns all credential categories
func GetCredentialCategories() []CredentialCategory {
	return []CredentialCategory{
		{ID: "identity", DisplayName: "Identity", Description: "Identity and personal information credentials"},
		{ID: "employment", DisplayName: "Employment", Description: "Employment and professional credentials"},
		{ID: "education", DisplayName: "Education", Description: "Educational and academic credentials"},
		{ID: "financial", DisplayName: "Financial", Description: "Financial and banking credentials"},
		{ID: "healthcare", DisplayName: "Healthcare", Description: "Health and medical credentials"},
		{ID: "legal", DisplayName: "Legal & Compliance", Description: "Legal and regulatory compliance credentials"},
		{ID: "access", DisplayName: "Access & Authorization", Description: "Access control and authorization credentials"},
		{ID: "business", DisplayName: "Business", Description: "Business and organizational credentials"},
	}
}

// GetCredentialTypes returns all supported credential types
func GetCredentialTypes() []CredentialTypeInfo {
	return []CredentialTypeInfo{
		// Identity Credentials
		{
			Type:         "IdentityCredential",
			DisplayName:  "Identity",
			Description:  "Basic identity information including name, date of birth, and photo",
			Category:     "identity",
			CommonClaims: []string{"full_name", "first_name", "last_name", "date_of_birth", "photo", "gender"},
		},
		{
			Type:         "KYCCredential",
			DisplayName:  "KYC Verification",
			Description:  "Know Your Customer verification for regulatory compliance",
			Category:     "identity",
			CommonClaims: []string{"full_name", "date_of_birth", "nationality", "document_number", "document_type", "address", "kyc_level", "verified_at"},
		},
		{
			Type:         "GovernmentIDCredential",
			DisplayName:  "Government ID",
			Description:  "Government-issued identification document",
			Category:     "identity",
			CommonClaims: []string{"full_name", "date_of_birth", "document_number", "document_type", "issuing_country", "issue_date", "expiry_date", "photo"},
		},
		{
			Type:         "PassportCredential",
			DisplayName:  "Passport",
			Description:  "International passport credential",
			Category:     "identity",
			CommonClaims: []string{"full_name", "date_of_birth", "passport_number", "nationality", "issuing_country", "issue_date", "expiry_date", "photo", "mrz"},
		},
		{
			Type:         "DriverLicenseCredential",
			DisplayName:  "Driver's License",
			Description:  "Driver's license credential",
			Category:     "identity",
			CommonClaims: []string{"full_name", "date_of_birth", "license_number", "license_class", "issuing_state", "issue_date", "expiry_date", "address", "photo"},
		},
		{
			Type:         "NationalIDCredential",
			DisplayName:  "National ID",
			Description:  "National identity card credential",
			Category:     "identity",
			CommonClaims: []string{"full_name", "date_of_birth", "national_id_number", "nationality", "address", "photo"},
		},
		{
			Type:         "ResidencyCredential",
			DisplayName:  "Proof of Residency",
			Description:  "Proof of residence or address verification",
			Category:     "identity",
			CommonClaims: []string{"full_name", "address", "city", "state", "postal_code", "country", "residency_since", "verified_at"},
		},
		{
			Type:         "CitizenshipCredential",
			DisplayName:  "Citizenship",
			Description:  "Citizenship status verification",
			Category:     "identity",
			CommonClaims: []string{"full_name", "citizenship_country", "citizenship_type", "acquired_date"},
		},
		{
			Type:         "AgeVerificationCredential",
			DisplayName:  "Age Verification",
			Description:  "Age verification credential (often used with ZKP)",
			Category:     "identity",
			CommonClaims: []string{"date_of_birth", "is_over_18", "is_over_21", "age_range"},
		},

		// Employment Credentials
		{
			Type:         "EmploymentCredential",
			DisplayName:  "Employment",
			Description:  "Current or past employment verification",
			Category:     "employment",
			CommonClaims: []string{"employer_name", "job_title", "department", "start_date", "end_date", "employment_type", "is_current"},
		},
		{
			Type:         "IncomeCredential",
			DisplayName:  "Income Verification",
			Description:  "Income and salary verification",
			Category:     "employment",
			CommonClaims: []string{"employer_name", "annual_income", "monthly_income", "currency", "income_type", "verification_date"},
		},
		{
			Type:         "ProfessionalLicenseCredential",
			DisplayName:  "Professional License",
			Description:  "Professional license (doctor, lawyer, engineer, etc.)",
			Category:     "employment",
			CommonClaims: []string{"full_name", "license_type", "license_number", "issuing_authority", "issue_date", "expiry_date", "status", "specialization"},
		},
		{
			Type:         "CertificationCredential",
			DisplayName:  "Professional Certification",
			Description:  "Professional certification or qualification",
			Category:     "employment",
			CommonClaims: []string{"full_name", "certification_name", "issuing_organization", "issue_date", "expiry_date", "credential_id"},
		},
		{
			Type:         "MembershipCredential",
			DisplayName:  "Professional Membership",
			Description:  "Professional association or organization membership",
			Category:     "employment",
			CommonClaims: []string{"full_name", "organization_name", "membership_type", "member_id", "join_date", "expiry_date", "status"},
		},
		{
			Type:         "BackgroundCheckCredential",
			DisplayName:  "Background Check",
			Description:  "Background check verification results",
			Category:     "employment",
			CommonClaims: []string{"full_name", "check_type", "check_date", "result", "provider", "valid_until"},
		},

		// Education Credentials
		{
			Type:         "EducationCredential",
			DisplayName:  "Education",
			Description:  "General education verification",
			Category:     "education",
			CommonClaims: []string{"full_name", "institution_name", "degree_type", "field_of_study", "graduation_date", "gpa"},
		},
		{
			Type:         "DegreeCredential",
			DisplayName:  "University Degree",
			Description:  "University or college degree credential",
			Category:     "education",
			CommonClaims: []string{"full_name", "institution_name", "degree_type", "degree_name", "field_of_study", "graduation_date", "honors", "gpa"},
		},
		{
			Type:         "DiplomaCredential",
			DisplayName:  "Diploma",
			Description:  "High school or secondary diploma credential",
			Category:     "education",
			CommonClaims: []string{"full_name", "institution_name", "diploma_type", "graduation_date", "gpa"},
		},
		{
			Type:         "TranscriptCredential",
			DisplayName:  "Academic Transcript",
			Description:  "Academic transcript with grades and courses",
			Category:     "education",
			CommonClaims: []string{"full_name", "institution_name", "courses", "grades", "gpa", "credits", "enrollment_period"},
		},
		{
			Type:         "CourseCompletionCredential",
			DisplayName:  "Course Completion",
			Description:  "Course or training completion certificate",
			Category:     "education",
			CommonClaims: []string{"full_name", "course_name", "provider", "completion_date", "duration", "grade", "certificate_id"},
		},
		{
			Type:         "SkillCredential",
			DisplayName:  "Verified Skill",
			Description:  "Verified skill or competency attestation",
			Category:     "education",
			CommonClaims: []string{"full_name", "skill_name", "proficiency_level", "verified_by", "verification_date", "evidence"},
		},

		// Financial Credentials
		{
			Type:         "BankAccountCredential",
			DisplayName:  "Bank Account",
			Description:  "Bank account ownership verification",
			Category:     "financial",
			CommonClaims: []string{"account_holder_name", "bank_name", "account_type", "account_number_last4", "verified_at"},
		},
		{
			Type:         "CreditScoreCredential",
			DisplayName:  "Credit Score",
			Description:  "Credit score verification",
			Category:     "financial",
			CommonClaims: []string{"full_name", "credit_score", "score_range", "credit_bureau", "report_date"},
		},
		{
			Type:         "AccreditedInvestorCredential",
			DisplayName:  "Accredited Investor",
			Description:  "Accredited investor status verification",
			Category:     "financial",
			CommonClaims: []string{"full_name", "qualification_type", "verified_at", "valid_until", "verifier"},
		},
		{
			Type:         "InsuranceCredential",
			DisplayName:  "Insurance",
			Description:  "Insurance policy verification",
			Category:     "financial",
			CommonClaims: []string{"policy_holder_name", "insurance_type", "policy_number", "provider", "coverage_amount", "start_date", "end_date"},
		},
		{
			Type:         "TaxResidencyCredential",
			DisplayName:  "Tax Residency",
			Description:  "Tax residency status verification",
			Category:     "financial",
			CommonClaims: []string{"full_name", "tax_residency_country", "tax_id", "tax_year", "verified_at"},
		},

		// Healthcare Credentials
		{
			Type:         "HealthCredential",
			DisplayName:  "Health Record",
			Description:  "General health information credential",
			Category:     "healthcare",
			CommonClaims: []string{"full_name", "blood_type", "allergies", "conditions", "medications"},
		},
		{
			Type:         "VaccinationCredential",
			DisplayName:  "Vaccination Record",
			Description:  "Vaccination or immunization record",
			Category:     "healthcare",
			CommonClaims: []string{"full_name", "vaccine_name", "vaccine_type", "dose_number", "vaccination_date", "provider", "lot_number", "next_dose_date"},
		},
		{
			Type:         "HealthInsuranceCredential",
			DisplayName:  "Health Insurance",
			Description:  "Health insurance verification",
			Category:     "healthcare",
			CommonClaims: []string{"policy_holder_name", "insurance_provider", "policy_number", "group_number", "coverage_type", "start_date", "end_date"},
		},
		{
			Type:         "PrescriptionCredential",
			DisplayName:  "Prescription",
			Description:  "Prescription authorization credential",
			Category:     "healthcare",
			CommonClaims: []string{"patient_name", "medication_name", "dosage", "prescriber_name", "prescription_date", "refills_remaining", "pharmacy"},
		},
		{
			Type:         "MedicalLicenseCredential",
			DisplayName:  "Medical License",
			Description:  "Medical practitioner license credential",
			Category:     "healthcare",
			CommonClaims: []string{"full_name", "license_type", "license_number", "specialty", "issuing_authority", "issue_date", "expiry_date", "status"},
		},
		{
			Type:         "DisabilityCredential",
			DisplayName:  "Disability Status",
			Description:  "Disability status verification",
			Category:     "healthcare",
			CommonClaims: []string{"full_name", "disability_type", "disability_level", "verified_by", "verification_date", "accommodations"},
		},

		// Legal & Compliance Credentials
		{
			Type:         "AMLCredential",
			DisplayName:  "AML Clearance",
			Description:  "Anti-money laundering clearance verification",
			Category:     "legal",
			CommonClaims: []string{"full_name", "check_date", "result", "risk_level", "provider", "valid_until"},
		},
		{
			Type:         "SanctionsCheckCredential",
			DisplayName:  "Sanctions Check",
			Description:  "Sanctions screening result credential",
			Category:     "legal",
			CommonClaims: []string{"full_name", "check_date", "result", "lists_checked", "provider"},
		},
		{
			Type:         "PEPCheckCredential",
			DisplayName:  "PEP Check",
			Description:  "Politically exposed person check credential",
			Category:     "legal",
			CommonClaims: []string{"full_name", "check_date", "is_pep", "pep_type", "provider"},
		},
		{
			Type:         "ConsentCredential",
			DisplayName:  "Consent Record",
			Description:  "Consent or authorization record credential",
			Category:     "legal",
			CommonClaims: []string{"subject_name", "consent_type", "purpose", "granted_to", "consent_date", "expiry_date", "scope"},
		},
		{
			Type:         "PowerOfAttorneyCredential",
			DisplayName:  "Power of Attorney",
			Description:  "Legal power of attorney authorization",
			Category:     "legal",
			CommonClaims: []string{"principal_name", "agent_name", "poa_type", "scope", "effective_date", "expiry_date", "jurisdiction"},
		},

		// Access & Authorization Credentials
		{
			Type:         "AccessCredential",
			DisplayName:  "Access Authorization",
			Description:  "General access authorization credential",
			Category:     "access",
			CommonClaims: []string{"holder_name", "access_type", "resource", "permissions", "granted_by", "start_date", "end_date"},
		},
		{
			Type:         "EventTicketCredential",
			DisplayName:  "Event Ticket",
			Description:  "Event or venue access ticket credential",
			Category:     "access",
			CommonClaims: []string{"holder_name", "event_name", "venue", "event_date", "seat", "ticket_type", "ticket_id"},
		},
		{
			Type:         "SubscriptionCredential",
			DisplayName:  "Subscription",
			Description:  "Service subscription status credential",
			Category:     "access",
			CommonClaims: []string{"subscriber_name", "service_name", "plan_type", "start_date", "end_date", "status"},
		},
		{
			Type:         "LoyaltyCredential",
			DisplayName:  "Loyalty Program",
			Description:  "Loyalty program membership credential",
			Category:     "access",
			CommonClaims: []string{"member_name", "program_name", "member_id", "tier", "points_balance", "join_date"},
		},
		{
			Type:         "VIPCredential",
			DisplayName:  "VIP Status",
			Description:  "VIP or premium status credential",
			Category:     "access",
			CommonClaims: []string{"holder_name", "vip_level", "benefits", "granted_by", "start_date", "end_date"},
		},

		// Business Credentials
		{
			Type:         "BusinessCredential",
			DisplayName:  "Business Verification",
			Description:  "Business or company verification credential",
			Category:     "business",
			CommonClaims: []string{"business_name", "registration_number", "business_type", "jurisdiction", "registration_date", "status", "address"},
		},
		{
			Type:         "BusinessRegistrationCredential",
			DisplayName:  "Business Registration",
			Description:  "Official business registration credential",
			Category:     "business",
			CommonClaims: []string{"business_name", "registration_number", "registration_authority", "registration_date", "business_type", "jurisdiction"},
		},
		{
			Type:         "AuthorizedRepresentativeCredential",
			DisplayName:  "Authorized Representative",
			Description:  "Authorization to act on behalf of organization",
			Category:     "business",
			CommonClaims: []string{"representative_name", "organization_name", "role", "authorization_scope", "start_date", "end_date"},
		},
		{
			Type:         "BoardMemberCredential",
			DisplayName:  "Board Member",
			Description:  "Board member status credential",
			Category:     "business",
			CommonClaims: []string{"member_name", "organization_name", "position", "appointment_date", "term_end_date", "committees"},
		},
	}
}

// GetCredentialTypesResponse returns the full credential types response
func GetCredentialTypesResponse() *CredentialTypesResponse {
	return &CredentialTypesResponse{
		CredentialTypes: GetCredentialTypes(),
		Categories:      GetCredentialCategories(),
	}
}

// GetCredentialTypesByCategory returns credential types filtered by category
func GetCredentialTypesByCategory(category string) []CredentialTypeInfo {
	allTypes := GetCredentialTypes()
	if category == "" {
		return allTypes
	}

	var filtered []CredentialTypeInfo
	for _, ct := range allTypes {
		if ct.Category == category {
			filtered = append(filtered, ct)
		}
	}
	return filtered
}
