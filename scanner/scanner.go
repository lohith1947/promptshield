package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// Detection represents a single finding from a scan
type Detection struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Match    string `json:"match"`   // the actual text found
	Position int    `json:"position"` // character offset in original text
}

// Scanner scans text for sensitive patterns
type Scanner struct {
	patterns []Pattern
}

// New creates a new Scanner with all built-in patterns
func New() *Scanner {
	return &Scanner{
		patterns: GetPatterns(),
	}
}

// Redact replaces detected sensitive values with placeholders
func (s *Scanner) Redact(text string) (string, []Detection, bool) {
	detections := s.Scan(text)
	if len(detections) == 0 {
		return text, detections, false
	}

	result := text
	for i, d := range detections {
		token := fmt.Sprintf("[REDACTED_%s_%d]", d.Name, i+1)
		result = regexp.MustCompile(regexp.QuoteMeta(d.Match)).ReplaceAllString(result, token)
	}

	return result, detections, true
}

// Scan detects all sensitive patterns in text
func (s *Scanner) Scan(text string) []Detection {
	var detections []Detection

	for _, p := range s.patterns {
		// Generic_Password captures a label + value ("password is Panda@167").
		// Only the value (regex group 2) counts as the match, so masking
		// replaces just the secret and preserves the surrounding words instead
		// of swallowing the whole "password is ..." phrase.
		if p.Name == "Generic_Password" {
			locs := p.Regex.FindAllStringSubmatchIndex(text, -1)
			for _, loc := range locs {
				if len(loc) < 6 {
					continue
				}
				valStart, valEnd := loc[4], loc[5]
				if valStart < 0 || valEnd < 0 {
					continue
				}
				detections = append(detections, Detection{
					Name:     p.Name,
					Severity: p.Severity,
					Match:    text[valStart:valEnd],
					Position: valStart,
				})
			}
			continue
		}

		matches := p.Regex.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			match := text[loc[0]:loc[1]]

			// Validate credit cards with Luhn
			if p.Name == "CreditCard_Visa" || p.Name == "CreditCard_Mastercard" ||
				p.Name == "CreditCard_Amex" || p.Name == "CreditCard_Discover" {
				if !luhnCheck(match) {
					continue
				}
			}

			// Filter IPv4 false positives for private ranges + invalid octets
			if p.Name == "IPv4" {
				if !isValidIPv4(match) || isPrivateIP(match) {
					continue
				}
			}

			detections = append(detections, Detection{
				Name:     p.Name,
				Severity: p.Severity,
				Match:    match,
				Position: loc[0],
			})
		}
	}

	return detections
}

// MaskValues replaces every detection match with a placeholder token.
// It is used to scrub leaked data out of AI responses before the client sees it.
func MaskValues(text string, detections []Detection, prefix string) string {
	result := text
	counts := map[string]int{}
	for _, d := range detections {
		if d.Match == "" {
			continue
		}
		counts[d.Name]++
		token := fmt.Sprintf("[%s_%s_%d]", prefix, d.Name, counts[d.Name])
		result = strings.ReplaceAll(result, d.Match, token)
	}
	return result
}

// luhnCheck validates a credit card number using the Luhn algorithm
func luhnCheck(num string) bool {
	// Strip dashes and spaces
	digits := regexp.MustCompile(`[\s-]`).ReplaceAllString(num, "")
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	// Reject numbers like 0000-...-0000 that pass the checksum but aren't real
	allSame := true
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}
	return sum%10 == 0
}

// isValidIPv4 rejects malformed octets like 999.1.1.1 or "256" values
func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		n := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
			n = n*10 + int(ch-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// isPrivateIP checks if an IPv4 is in private ranges
func isPrivateIP(ip string) bool {
	privatePatterns := []string{
		`^10\.`,          // 10.0.0.0/8
		`^172\.(1[6-9]|2\d|3[01])\.`, // 172.16.0.0/12
		`^192\.168\.`,    // 192.168.0.0/16
		`^127\.`,         // localhost
		`^0\.`,           // localhost
	}
	for _, p := range privatePatterns {
		if matched, _ := regexp.MatchString(p, ip); matched {
			return true
		}
	}
	return false
}
