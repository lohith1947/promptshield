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

func TestIsValidIPv4(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"255.255.255.255", true},
		{"999.1.1.1", false},
		{"256.0.0.1", false},
		{"1.2.3", false},
		{"1.2.3.4.5", false},
		{"a.b.c.d", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isValidIPv4(tt.ip); got != tt.want {
				t.Errorf("isValidIPv4(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestScanIPv4RejectsInvalidOctets(t *testing.T) {
	s := New()
	for _, tt := range []struct {
		input string
		want  bool
	}{
		{"server at 203.0.113.7", true},
		{"version 999.1.1.1 here", false},
		{"octet 256.0.0.1 invalid", false},
	} {
		detections := s.Scan(tt.input)
		found := false
		for _, d := range detections {
			if d.Name == "IPv4" {
				found = true
			}
		}
		if found != tt.want {
			t.Errorf("Scan(%q): IPv4 detected = %v, want %v", tt.input, found, tt.want)
		}
	}
}

func TestScanSSNLeadingZeroExcluded(t *testing.T) {
	s := New()
	detections := s.Scan("SSN: 012345678")
	for _, d := range detections {
		if d.Name == "SSN_NoDash" {
			t.Error("expected leading-zero 9-digit string to be excluded")
		}
	}
}

func TestScanPassportRequiresTwoLetters(t *testing.T) {
	s := New()
	// One letter + digits is a common order/product code; tightened to 2 letters.
	detections := s.Scan("order A1234567 was shipped")
	for _, d := range detections {
		if d.Name == "Passport" {
			t.Error("expected single-letter passport pattern to be excluded")
		}
	}
	det := s.Scan("passport AB1234567")
	found := false
	for _, d := range det {
		if d.Name == "Passport" {
			found = true
		}
	}
	if !found {
		t.Error("expected two-letter passport pattern to be detected")
	}
}

func TestScanNewProviderKeys(t *testing.T) {
	s := New()
	tests := []struct {
		input string
		name  string
	}{
		{"gitlab token " + "glpat-" + "xYzAbC1234567890abcd", "GitLab_PAT"},
		{"groq key " + "gsk_" + "AbCdEf1234567890abcdEf1234", "Groq_Key"},
		{"perplexity " + "pplx-" + "8f3kLmNopQrStUvWxYzA1", "Perplexity_Key"},
		{"sendgrid " + "SG." + "7Qx3Kd9F2aZj1LmNe8VbXc0d.YsGqP4r8LjW9NfH2vTzC5a", "SendGrid_Key"},
		{"twilio api sid " + "SK" + "1f0b56789abcdef0123456789abcdef1", "Twilio_API_SID"},
		{"npm token " + "npm_" + "8fA2kLmN3bCdE4fGh5iJkLmN6oPqRsT7uVwXyZ", "npm_Token"},
		{"hf token " + "hf_" + "dJfL9kR2mT8bV4nH6pQ1sW5xZ7aC3e", "HuggingFace_Token"},
		{"discord token " + "MTIzNDU2Nzg5MDEyMzQ1Ng" + "." + "5fQ2bW" + "." + "0V8cLfW3k6p9ZtHsXqR2nBmKeY1dCjFlZaGxYv3t", "Discord_Token"},
		{"gemini api key " + "AIzaSy" + "7dFj9kLmNoPqRsT2uVwXyZ3aBcDeFgH4", "Gemini_API_Key"},
		{"grok api key " + "xai-" + "8f3kLmNopQrStUvWxYzA1B2", "xAI_API_Key"},
		{"azure openai api key: " + "5f3c4d2b7a91e8f6c40d5a2b9e7f3c81d2b6a4f5", "Azure_OpenAI_Key"},
		{"gcp key {\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nabcy\"}", "GCP_Service_Account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detections := s.Scan(tt.input)
			found := false
			for _, d := range detections {
				if d.Name == tt.name {
					found = true
				}
			}
			if !found {
				t.Errorf("Scan(%q): %s not detected", tt.input, tt.name)
			}
		})
	}
}

func TestScanPasswordIsColonForm(t *testing.T) {
	s := New()
	detections := s.Scan("my vault password is: MidnightFox!")
	found := false
	for _, d := range detections {
		if d.Name == "Generic_Password" && d.Match == "MidnightFox!" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'password is: VALUE' to be detected with value-only match")
	}
}

func TestScanPasswordValueOnlyVariants(t *testing.T) {
	s := New()
	for _, tt := range []struct {
		input string
		want  string
	}{
		{"my password is: MidnightFox!", "MidnightFox!"},
		{"my aws password was: ThunderStorm!", "ThunderStorm!"},
	} {
		detections := s.Scan(tt.input)
		var match string
		for _, d := range detections {
			if d.Name == "Generic_Password" {
				match = d.Match
			}
		}
		if match != tt.want {
			t.Errorf("Scan(%q): match = %q, want %q", tt.input, match, tt.want)
		}
	}
}
