package kmip

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const kmipPath = "/kmip/2_1"

// Client sends KMIP 2.1 JSON TTLV operations to an Eviden KMS instance.
type Client struct {
	httpClient *http.Client
	kmsAddr    string
	token      string // non-empty when using token auth
}

// NewClient constructs and validates a Client from the provided Config.
// It establishes the TLS configuration (mTLS or standard TLS) but does not
// make any network calls.
func NewClient(cfg *Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid KMS config: %w", err)
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	httpClient := &http.Client{Transport: transport}

	var token string
	if cfg.TokenAuth != nil {
		token = cfg.TokenAuth.Token
		if token == "" {
			token = os.Getenv("KMS_API_TOKEN")
		}
	}

	return &Client{
		httpClient: httpClient,
		kmsAddr:    strings.TrimRight(cfg.KMSAddr, "/"),
		token:      token,
	}, nil
}

// Do sends a bare KMIP 2.1 operation to POST /kmip/2_1 and returns the
// response TTLV. A KMIP OperationFailed result is returned as a *KMIPError.
func (c *Client) Do(ctx context.Context, req TTLV) (TTLV, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return TTLV{}, fmt.Errorf("marshal KMIP request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.kmsAddr+kmipPath, bytes.NewReader(body))
	if err != nil {
		return TTLV{}, fmt.Errorf("create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return TTLV{}, fmt.Errorf("HTTP POST %s: %w", kmipPath, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return TTLV{}, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return TTLV{}, fmt.Errorf("KMS returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result TTLV
	if err := json.Unmarshal(respBody, &result); err != nil {
		return TTLV{}, fmt.Errorf("unmarshal KMIP response: %w", err)
	}

	// Check for KMIP-level OperationFailed inside the response.
	if err := checkKMIPError(result); err != nil {
		return TTLV{}, err
	}

	return result, nil
}

// checkKMIPError inspects the top-level response TTLV for a ResultStatus of
// OperationFailed and returns a *KMIPError when found.
func checkKMIPError(resp TTLV) error {
	children, err := childrenOf(resp)
	if err != nil {
		return nil // not a structure; pass through
	}
	for _, child := range children {
		if child.Tag == "ResultStatus" {
			if s, ok := stringValue(child); ok && s == "OperationFailed" {
				reason, message := "", ""
				if rc, ok := findChild(children, "ResultReason"); ok {
					reason, _ = stringValue(rc)
				}
				if mc, ok := findChild(children, "ResultMessage"); ok {
					message, _ = stringValue(mc)
				}
				return &KMIPError{ResultReason: reason, ResultMessage: message}
			}
		}
	}
	return nil
}

// buildTLSConfig constructs a *tls.Config from the given Config.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // controlled by operator config
		MinVersion:         tls.VersionTLS12,
	}

	// Load CA certificate pool.
	if cfg.CACertPath != "" {
		caPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %q: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates found in %q", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	// Load mTLS client certificate.
	if cfg.CertAuth != nil {
		cert, err := tls.LoadX509KeyPair(cfg.CertAuth.ClientCertPath, cfg.CertAuth.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
