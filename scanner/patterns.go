package scanner

import "regexp"

// Pattern represents a single PII detection rule
type Pattern struct {
	Name      string
	Regex     *regexp.Regexp
	Severity  string // "critical", "high", "medium"
	Blockable bool
}

// GetPatterns returns all detection patterns grouped by category
func GetPatterns() []Pattern {
	return []Pattern{
		// === IDENTITY (Critical) ===
		{Name: "SSN", Regex: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Severity: "critical", Blockable: true},
		{Name: "SSN_NoDash", Regex: regexp.MustCompile(`\b\d{9}\b`), Severity: "critical", Blockable: true},
		{Name: "Passport", Regex: regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`), Severity: "critical", Blockable: true},

		// === FINANCIAL (Critical) ===
		{Name: "CreditCard_Visa", Regex: regexp.MustCompile(`\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), Severity: "critical", Blockable: true},
		{Name: "CreditCard_Mastercard", Regex: regexp.MustCompile(`\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), Severity: "critical", Blockable: true},
		{Name: "CreditCard_Amex", Regex: regexp.MustCompile(`\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b`), Severity: "critical", Blockable: true},
		{Name: "CreditCard_Discover", Regex: regexp.MustCompile(`\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), Severity: "critical", Blockable: true},
		{Name: "IBAN", Regex: regexp.MustCompile(`\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,7}\b`), Severity: "critical", Blockable: true},

		// === CREDENTIALS (Critical) ===
		{Name: "AWS_Access_Key", Regex: regexp.MustCompile(`\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b`), Severity: "critical", Blockable: true},
		{Name: "AWS_Secret_Key", Regex: regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=]+[A-Za-z0-9/+=]{40}`), Severity: "critical", Blockable: true},
		{Name: "GitHub_Token", Regex: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,}\b`), Severity: "critical", Blockable: true},
		{Name: "GitHub_Fine_Grained", Regex: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`), Severity: "critical", Blockable: true},
		{Name: "Slack_Token", Regex: regexp.MustCompile(`\bxox[bpoas]-[A-Za-z0-9-]+\b`), Severity: "critical", Blockable: true},
		{Name: "Slack_Webhook", Regex: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}`), Severity: "critical", Blockable: true},
		{Name: "OpenAI_Key", Regex: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), Severity: "critical", Blockable: true},
		{Name: "Anthropic_Key", Regex: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), Severity: "critical", Blockable: true},
		{Name: "Google_API_Key", Regex: regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`), Severity: "critical", Blockable: true},
		{Name: "Stripe_Key", Regex: regexp.MustCompile(`\b(rk_live|sk_live|rk_test|sk_test)_[A-Za-z0-9]{20,}\b`), Severity: "critical", Blockable: true},
		{Name: "Private_Key_PEM", Regex: regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`), Severity: "critical", Blockable: true},
		{Name: "JWT_Token", Regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), Severity: "critical", Blockable: true},
		{Name: "Generic_Password", Regex: regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key)\b\s*(?:[:=]|\b(?:is|was|had)\b)?\s*["']?[^\s"']{8,}["']?`), Severity: "high", Blockable: true},

		// === CONTACT (High) ===
		{Name: "Email", Regex: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), Severity: "high", Blockable: false},
		{Name: "Phone_US", Regex: regexp.MustCompile(`\b(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b`), Severity: "high", Blockable: false},

		// === NETWORK (Medium) ===
		{Name: "IPv4", Regex: regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), Severity: "medium", Blockable: false},
		{Name: "IPv6", Regex: regexp.MustCompile(`\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`), Severity: "medium", Blockable: false},
	}
}
