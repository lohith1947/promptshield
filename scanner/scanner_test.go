package scanner

import "testing"

func TestScanSSN(t *testing.T) {
	s := New()
	tests := []struct {
		input string
		want  int
		name  string
	}{
		{"My SSN is 123-45-6789", 1, "SSN with dashes"},
		{"SSN: 123456789", 1, "SSN without dashes"},
		{"No sensitive data here", 0, "No SSN"},
		{"Two SSNs: 123-45-6789 and 987-65-4321", 2, "Two SSNs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detections := s.Scan(tt.input)
			if len(detections) != tt.want {
				t.Errorf("Scan(%q) = %d detections, want %d", tt.input, len(detections), tt.want)
			}
		})
	}
}

func TestScanEmail(t *testing.T) {
	s := New()
	detections := s.Scan("Contact me at john.doe@company.com")
	found := false
	for _, d := range detections {
		if d.Name == "Email" {
			found = true
		}
	}
	if !found {
		t.Error("Failed to detect email address")
	}
}

func TestScanAWSSecretKey(t *testing.T) {
	s := New()
	input := "My key: AKIAIOSFODNN7EXAMPLE"
	detections := s.Scan(input)
	found := false
	for _, d := range detections {
		if d.Name == "AWS_Access_Key" {
			found = true
		}
	}
	if !found {
		t.Error("Failed to detect AWS access key")
	}
}

func TestScanGitHubToken(t *testing.T) {
	s := New()
	input := "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	detections := s.Scan(input)
	found := false
	for _, d := range detections {
		if d.Name == "GitHub_Token" {
			found = true
		}
	}
	if !found {
		t.Error("Failed to detect GitHub token")
	}
}

func TestScanGenericPassword(t *testing.T) {
	s := New()
	tests := []struct {
		input string
		want  bool
		name  string
	}{
		{"my password is Panda@167", true, "natural language 'is'"},
		{"password was Panda@167", true, "natural language 'was'"},
		{"password: Panda@167", true, "colon form"},
		{"password=Panda@167", true, "equals form"},
		{"password Panda@167", true, "bare whitespace form"},
		{"What is your password", false, "no value present"},
		{"my password is very long", false, "no plausible value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detections := s.Scan(tt.input)
			found := false
			for _, d := range detections {
				if d.Name == "Generic_Password" {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("Scan(%q): Generic_Password detected = %v, want %v", tt.input, found, tt.want)
			}
		})
	}
}

// TestScanGenericPasswordExtractsValueOnly ensures the detection Match is just
// the sensitive value, not the whole "password is ..." phrase, so masking keeps
// the surrounding words intact.
func TestScanGenericPasswordExtractsValueOnly(t *testing.T) {
	s := New()
	for _, tt := range []struct {
		input string
		want  string
	}{
		{"my password is Panda@167", "Panda@167"},
		{"password was Panda@167", "Panda@167"},
		{"password: Panda@167", "Panda@167"},
		{"password=Panda@167", "Panda@167"},
	} {
		detections := s.Scan(tt.input)
		var match string
		for _, d := range detections {
			if d.Name == "Generic_Password" {
				match = d.Match
			}
		}
		if match != tt.want {
			t.Errorf("Scan(%q): Generic_Password match = %q, want %q", tt.input, match, tt.want)
		}
	}
}

func TestRedact(t *testing.T) {
	s := New()
	input := "Send to john@test.com and my SSN 123-45-6789"
	redacted, detections, hadSensitive := s.Redact(input)

	if !hadSensitive {
		t.Error("Expected redaction to flag sensitive data")
	}
	if len(detections) < 2 {
		t.Errorf("Expected 2+ detections, got %d", len(detections))
	}
	// Redacted text should not contain the original email
	if redacted == input {
		t.Error("Redacted text should differ from input")
	}
}

func TestLuhnValidation(t *testing.T) {
	tests := []struct {
		num  string
		want bool
	}{
		{"4111-1111-1111-1111", true},  // Visa test number
		{"5500-0000-0000-0004", true},  // Mastercard test number
		{"1234-5678-9012-3456", false}, // Random
		{"0000-0000-0000-0000", false}, // All zeros
	}

	for _, tt := range tests {
		t.Run(tt.num, func(t *testing.T) {
			got := luhnCheck(tt.num)
			if got != tt.want {
				t.Errorf("luhnCheck(%q) = %v, want %v", tt.num, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
