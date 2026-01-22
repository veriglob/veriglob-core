package services

import (
	"testing"
)

func TestGetCredentialCategories(t *testing.T) {
	categories := GetCredentialCategories()

	if len(categories) != 8 {
		t.Errorf("Expected 8 categories, got %d", len(categories))
	}

	// Verify expected categories exist
	expectedIDs := []string{"identity", "employment", "education", "financial", "healthcare", "legal", "access", "business"}
	categoryMap := make(map[string]bool)
	for _, c := range categories {
		categoryMap[c.ID] = true
	}

	for _, id := range expectedIDs {
		if !categoryMap[id] {
			t.Errorf("Expected category %s not found", id)
		}
	}

	// Verify each category has required fields
	for _, c := range categories {
		if c.ID == "" {
			t.Error("Category ID should not be empty")
		}
		if c.DisplayName == "" {
			t.Error("Category DisplayName should not be empty")
		}
		if c.Description == "" {
			t.Error("Category Description should not be empty")
		}
	}
}

func TestGetCredentialTypes(t *testing.T) {
	types := GetCredentialTypes()

	if len(types) == 0 {
		t.Error("Expected at least one credential type")
	}

	// Verify each type has required fields
	for _, ct := range types {
		if ct.Type == "" {
			t.Error("CredentialType Type should not be empty")
		}
		if ct.DisplayName == "" {
			t.Errorf("CredentialType %s DisplayName should not be empty", ct.Type)
		}
		if ct.Description == "" {
			t.Errorf("CredentialType %s Description should not be empty", ct.Type)
		}
		if ct.Category == "" {
			t.Errorf("CredentialType %s Category should not be empty", ct.Type)
		}
		if len(ct.CommonClaims) == 0 {
			t.Errorf("CredentialType %s should have at least one common claim", ct.Type)
		}
	}

	// Verify some expected credential types exist
	expectedTypes := []string{"IdentityCredential", "KYCCredential", "EmploymentCredential", "DegreeCredential"}
	typeMap := make(map[string]bool)
	for _, ct := range types {
		typeMap[ct.Type] = true
	}

	for _, typ := range expectedTypes {
		if !typeMap[typ] {
			t.Errorf("Expected credential type %s not found", typ)
		}
	}
}

func TestGetCredentialTypesByCategory(t *testing.T) {
	// Test identity category
	identityTypes := GetCredentialTypesByCategory("identity")
	if len(identityTypes) == 0 {
		t.Error("Expected at least one identity credential type")
	}
	for _, ct := range identityTypes {
		if ct.Category != "identity" {
			t.Errorf("Expected category 'identity', got %s", ct.Category)
		}
	}

	// Test employment category
	employmentTypes := GetCredentialTypesByCategory("employment")
	if len(employmentTypes) == 0 {
		t.Error("Expected at least one employment credential type")
	}
	for _, ct := range employmentTypes {
		if ct.Category != "employment" {
			t.Errorf("Expected category 'employment', got %s", ct.Category)
		}
	}

	// Test empty category returns all types
	allTypes := GetCredentialTypesByCategory("")
	if len(allTypes) != len(GetCredentialTypes()) {
		t.Error("Empty category should return all credential types")
	}

	// Test nonexistent category returns empty
	noTypes := GetCredentialTypesByCategory("nonexistent")
	if len(noTypes) != 0 {
		t.Errorf("Nonexistent category should return empty slice, got %d types", len(noTypes))
	}
}

func TestGetCredentialTypesResponse(t *testing.T) {
	response := GetCredentialTypesResponse()

	if response == nil {
		t.Fatal("Response should not be nil")
	}

	if len(response.Categories) != 8 {
		t.Errorf("Expected 8 categories, got %d", len(response.Categories))
	}

	if len(response.CredentialTypes) == 0 {
		t.Error("Expected at least one credential type")
	}

	// Verify all credential types have valid categories
	categoryMap := make(map[string]bool)
	for _, c := range response.Categories {
		categoryMap[c.ID] = true
	}

	for _, ct := range response.CredentialTypes {
		if !categoryMap[ct.Category] {
			t.Errorf("Credential type %s has invalid category %s", ct.Type, ct.Category)
		}
	}
}

func TestCredentialTypesUniqueness(t *testing.T) {
	types := GetCredentialTypes()
	typeMap := make(map[string]bool)

	for _, ct := range types {
		if typeMap[ct.Type] {
			t.Errorf("Duplicate credential type found: %s", ct.Type)
		}
		typeMap[ct.Type] = true
	}
}

func TestCategoryUniqueness(t *testing.T) {
	categories := GetCredentialCategories()
	idMap := make(map[string]bool)

	for _, c := range categories {
		if idMap[c.ID] {
			t.Errorf("Duplicate category ID found: %s", c.ID)
		}
		idMap[c.ID] = true
	}
}
