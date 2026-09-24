package detect

import "regexp"

func init() {
	register(regexRule{
		id:       "aws-access-key-id",
		severity: Critical,
		desc:     "an AWS access key ID",
		re:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	})
	register(regexRule{
		id:       "aws-secret-access-key",
		severity: Critical,
		desc:     "an AWS secret access key, matched by its conventional variable name plus a 40-character key",
		re:       regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+]{40})['"]?`),
	})
	register(regexRule{
		id:       "github-pat",
		severity: Critical,
		desc:     "a classic GitHub personal access token",
		re:       regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
	})
	register(regexRule{
		id:       "github-fine-grained-pat",
		severity: Critical,
		desc:     "a fine-grained GitHub personal access token",
		re:       regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
	})
	register(regexRule{
		id:       "slack-token",
		severity: High,
		desc:     "a Slack API token",
		re:       regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	})
	register(regexRule{
		id:       "stripe-live-secret-key",
		severity: Critical,
		desc:     "a Stripe live-mode secret key",
		re:       regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
	})
	register(regexRule{
		id:       "google-api-key",
		severity: High,
		desc:     "a Google API key",
		re:       regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	})
	register(regexRule{
		id:       "private-key-block",
		severity: Critical,
		desc:     "a PEM private key block",
		re:       regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
	})
	register(regexRule{
		id:       "jwt",
		severity: High,
		desc:     "a JSON Web Token",
		re:       regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	})
	register(genericSecretRule{})
}
