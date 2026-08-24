package kmip

// Config holds the connection parameters for an Eviden KMS instance.
//
// Authentication: either CertAuth (mTLS) or TokenAuth (Bearer/API key) must be set,
// but not both.
type Config struct {
	// KMSAddr is the base URL of the KMS (e.g. "https://kms.example.com:9998").
	// Required.
	KMSAddr string

	// CACertPath is the PEM file used to verify the KMS TLS certificate.
	// Optional; when empty the system certificate pool is used.
	CACertPath string

	// InsecureSkipVerify disables TLS certificate verification.
	// For test environments only.
	InsecureSkipVerify bool

	// CertAuth holds mTLS client certificate credentials.
	// Mutually exclusive with TokenAuth.
	CertAuth *CertAuthConfig

	// TokenAuth holds a static Bearer token / API key.
	// Mutually exclusive with CertAuth.
	TokenAuth *TokenAuthConfig
}

// CertAuthConfig holds mTLS client certificate paths.
type CertAuthConfig struct {
	// ClientCertPath is the PEM file of the client certificate.
	ClientCertPath string
	// ClientKeyPath is the PEM file of the client private key.
	ClientKeyPath string
}

// TokenAuthConfig holds a static Bearer token or API key sent as
// "Authorization: Bearer <token>" on every request.
type TokenAuthConfig struct {
	// Token is the Bearer token or API key value.
	// May also be set via the KMS_API_TOKEN environment variable.
	Token string
}

// Validate returns an error if the configuration is missing required fields or
// has mutually exclusive options set simultaneously.
func (c *Config) Validate() error {
	if c.KMSAddr == "" {
		return errorf("kms_addr is required")
	}
	if c.CertAuth != nil && c.TokenAuth != nil {
		return errorf("cert_auth and token_auth are mutually exclusive: configure only one")
	}
	if c.CertAuth != nil {
		if c.CertAuth.ClientCertPath == "" {
			return errorf("cert_auth.client_cert_path is required")
		}
		if c.CertAuth.ClientKeyPath == "" {
			return errorf("cert_auth.client_key_path is required")
		}
	}
	return nil
}
