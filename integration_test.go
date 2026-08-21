//go:build integration

// Integration tests for the KMIP 2.1 Go client against a live Eviden KMS.
//
// Activated by the "integration" build tag. Environment variables:
//
//   KMS_TEST_ADDR    — KMS base URL (e.g. "https://127.0.0.1:9998")
//   KMS_CA_CERT      — PEM CA cert to verify the KMS TLS certificate (optional)
//   KMS_CLIENT_CERT  — PEM client certificate for mTLS authentication (optional)
//   KMS_CLIENT_KEY   — PEM client private key for mTLS authentication (optional)
//   KMS_TEST_TOKEN   — Static Bearer token / API key (optional, no-auth if unset)
//
// Run via mise (no-auth):
//   mise run test:live
//
// Run via mise (mTLS):
//   mise run test:live --mtls
//
// Or manually with mTLS:
//   KMS_TEST_ADDR=https://127.0.0.1:9998 \
//   KMS_CA_CERT=test_data/spire/certs/ca.crt \
//   KMS_CLIENT_CERT=test_data/spire/certs/spire-client.crt \
//   KMS_CLIENT_KEY=test_data/spire/certs/spire-client.key \
//     go test -v -count=1 -tags integration ./...

package kmip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// liveClient returns a *Client pointing at the live KMS.
// Skips the test if KMS_TEST_ADDR is not set.
// Supports mTLS via KMS_CA_CERT / KMS_CLIENT_CERT / KMS_CLIENT_KEY env vars,
// and static token auth via KMS_TEST_TOKEN.
func liveClient(t *testing.T) *Client {
	t.Helper()
	addr := os.Getenv("KMS_TEST_ADDR")
	if addr == "" {
		t.Skip("KMS_TEST_ADDR must be set for integration tests (e.g. https://127.0.0.1:9998)")
	}
	cfg := &Config{
		KMSAddr:    addr,
		CACertPath: os.Getenv("KMS_CA_CERT"),
	}
	clientCert := os.Getenv("KMS_CLIENT_CERT")
	clientKey := os.Getenv("KMS_CLIENT_KEY")
	if clientCert != "" && clientKey != "" {
		cfg.CertAuth = &CertAuthConfig{
			ClientCertPath: clientCert,
			ClientKeyPath:  clientKey,
		}
		t.Logf("mTLS enabled: cert=%s", clientCert)
	} else if token := os.Getenv("KMS_TEST_TOKEN"); token != "" {
		cfg.TokenAuth = &TokenAuthConfig{Token: token}
	}
	c, err := NewClient(cfg)
	require.NoError(t, err, "NewClient")
	return c
}

// destroyKeyPair destroys both keys of a CreateKeyPairResponse on test cleanup.
func destroyKeyPair(t *testing.T, c *Client, kp *CreateKeyPairResponse) {
	t.Helper()
	t.Cleanup(func() {
		_ = c.Destroy(context.Background(), kp.PrivateKeyUID)
		_ = c.Destroy(context.Background(), kp.PublicKeyUID)
	})
}

// ─── CreateKeyPair ───────────────────────────────────────────────────────────

func TestLiveCreateKeyPairAllTypes(t *testing.T) {
	c := liveClient(t)
	for _, tt := range []struct {
		name string
		kt   KeyType
	}{
		{"EC_P256", KeyTypeECP256},
		{"EC_P384", KeyTypeECP384},
		{"RSA_2048", KeyTypeRSA2048},
		{"RSA_4096", KeyTypeRSA4096},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := c.CreateKeyPair(context.Background(), tt.kt,
				[]string{"x-spire-server-id:live-test", "x-spire-key-id:x509-CA-A"})
			require.NoError(t, err)
			require.NotEmpty(t, kp.PrivateKeyUID)
			require.NotEmpty(t, kp.PublicKeyUID)
			t.Logf("priv=%s pub=%s", kp.PrivateKeyUID, kp.PublicKeyUID)
			destroyKeyPair(t, c, kp)
		})
	}
}

// ─── GetPublicKey ─────────────────────────────────────────────────────────────

func TestLiveGetPublicKey(t *testing.T) {
	c := liveClient(t)
	kp, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, nil)
	require.NoError(t, err)
	destroyKeyPair(t, c, kp)

	attrs, err := c.GetPublicKey(context.Background(), kp.PublicKeyUID)
	require.NoError(t, err)
	require.NotEmpty(t, attrs.PublicKeyPKIX)

	pub, err := x509.ParsePKIXPublicKey(attrs.PublicKeyPKIX)
	require.NoError(t, err, "PKIX data must parse as a valid public key")
	t.Logf("Public key type: %T", pub)
}

// ─── Locate ───────────────────────────────────────────────────────────────────

func TestLiveLocate(t *testing.T) {
	c := liveClient(t)
	tag := "x-spire-server-id:live-locate-test"

	kp1, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, []string{tag})
	require.NoError(t, err)
	destroyKeyPair(t, c, kp1)
	kp2, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, []string{tag})
	require.NoError(t, err)
	destroyKeyPair(t, c, kp2)

	uids, err := c.Locate(context.Background(), []string{tag})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(uids), 2)
	t.Logf("Located %d private keys with tag %q", len(uids), tag)
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

func TestLiveSignECDSA(t *testing.T) {
	c := liveClient(t)
	kp, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, nil)
	require.NoError(t, err)
	destroyKeyPair(t, c, kp)

	digest := make([]byte, 32) // SHA-256 pre-hash
	sig, err := c.Sign(context.Background(), kp.PrivateKeyUID, digest, HashSHA256, SigECDSA)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	t.Logf("ECDSA signature: %d bytes", len(sig))
}

func TestLiveSignRSAPKCS1(t *testing.T) {
	c := liveClient(t)
	kp, err := c.CreateKeyPair(context.Background(), KeyTypeRSA2048, nil)
	require.NoError(t, err)
	destroyKeyPair(t, c, kp)

	digest := make([]byte, 32)
	sig, err := c.Sign(context.Background(), kp.PrivateKeyUID, digest, HashSHA256, SigRSAPKCS1)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	t.Logf("RSA-PKCS1 signature: %d bytes", len(sig))
}

// ─── Destroy ──────────────────────────────────────────────────────────────────

func TestLiveDestroy(t *testing.T) {
	c := liveClient(t)
	kp, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, nil)
	require.NoError(t, err)

	require.NoError(t, c.Destroy(context.Background(), kp.PrivateKeyUID))
	require.NoError(t, c.Destroy(context.Background(), kp.PublicKeyUID))

	// Attempting to use the destroyed key must return an error.
	_, err = c.GetPublicKey(context.Background(), kp.PublicKeyUID)
	require.Error(t, err, "GetPublicKey on a destroyed key must return an error")
}

// ─── Certify + auto-discovery ────────────────────────────────────────────────

func TestLiveCertify(t *testing.T) {
	c := liveClient(t)

	// Create a CA key pair.
	caKP, err := c.CreateKeyPair(context.Background(), KeyTypeECP384, []string{"vault_pki_ca_live_test"})
	require.NoError(t, err)
	destroyKeyPair(t, c, caKP)

	// Create a self-signed CA certificate (sets CertificateLink on the private key).
	caCertUID, err := c.CreateSelfSignedCertificate(context.Background(), caKP.PublicKeyUID, "Live Test Root CA", CAExtension)
	require.NoError(t, err, "CreateSelfSignedCertificate")
	t.Cleanup(func() { _ = c.Destroy(context.Background(), caCertUID) })

	// Verify auto-discovery: GetLinkedCertificateUID should return the cert we just created.
	discoveredCertUID, err := c.GetLinkedCertificateUID(context.Background(), caKP.PrivateKeyUID)
	require.NoError(t, err, "GetLinkedCertificateUID (auto-discovery)")
	require.Equal(t, caCertUID, discoveredCertUID, "auto-discovered cert UID must match created cert UID")
	t.Logf("Auto-discovered CA cert UID: %s", discoveredCertUID)

	csrPEM := liveGenerateCSR(t)

	certResp, err := c.Certify(context.Background(), csrPEM, caKP.PrivateKeyUID, caCertUID, nil, 0)
	require.NoError(t, err)
	require.NotEmpty(t, certResp.CertUID)
	t.Logf("Signed certificate UID: %s", certResp.CertUID)
	t.Cleanup(func() { _ = c.Destroy(context.Background(), certResp.CertUID) })

	// Export and parse the signed certificate.
	certBytes, err := c.ExportCertificate(context.Background(), certResp.CertUID)
	require.NoError(t, err)
	require.NotEmpty(t, certBytes)

	cert, err := parseLiveCert(certBytes)
	require.NoError(t, err)
	t.Logf("Signed cert subject: %s", cert.Subject)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func liveGenerateCSR(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func parseLiveCert(b []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(b); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(b)
}
