package kmip

import (
	"context"
	"testing"
)

// newTestClient returns a Client configured to talk to the given FakeKMS.
func newTestClient(t *testing.T, f *FakeKMS) *Client {
	t.Helper()
	c, err := NewClient(&Config{
		KMSAddr:            f.URL(),
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestCreateKeyPair(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	tests := []struct {
		name string
		kt   KeyType
	}{
		{"EC_P256", KeyTypeECP256},
		{"EC_P384", KeyTypeECP384},
		{"RSA_2048", KeyTypeRSA2048},
		{"RSA_4096", KeyTypeRSA4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := c.CreateKeyPair(context.Background(), tt.kt, []string{"x-spire-server-id:test", "x-spire-key-id:x509-CA-A"})
			if err != nil {
				t.Fatalf("CreateKeyPair(%s): %v", tt.kt, err)
			}
			if resp.PrivateKeyUID == "" || resp.PublicKeyUID == "" {
				t.Fatalf("CreateKeyPair returned empty UIDs")
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	resp, err := c.CreateKeyPair(context.Background(), KeyTypeRSA2048, nil)
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	attrs, err := c.GetPublicKey(context.Background(), resp.PublicKeyUID)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if len(attrs.PublicKeyPKIX) == 0 {
		t.Fatal("GetPublicKey returned empty PKIX")
	}
}

func TestLocate(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	// Create two keys with different server IDs.
	_, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, []string{"x-spire-server-id:server-A"})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	_, err = c.CreateKeyPair(context.Background(), KeyTypeECP256, []string{"x-spire-server-id:server-B"})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	uids, err := c.Locate(context.Background(), []string{"x-spire-server-id:server-A"})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(uids) != 1 {
		t.Fatalf("Locate: expected 1 result, got %d", len(uids))
	}
}

func TestSign(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	resp, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, nil)
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	digest := make([]byte, 32) // SHA-256 digest
	sig, err := c.Sign(context.Background(), resp.PrivateKeyUID, digest, HashSHA256, SigECDSA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}
}

func TestDestroy(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	resp, err := c.CreateKeyPair(context.Background(), KeyTypeECP256, nil)
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	if err := c.Destroy(context.Background(), resp.PrivateKeyUID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// Key should be gone — Locate finds nothing.
	uids, err := c.Locate(context.Background(), nil)
	if err != nil {
		t.Fatalf("Locate after Destroy: %v", err)
	}
	for _, uid := range uids {
		if uid == resp.PrivateKeyUID {
			t.Fatal("Destroy did not remove key")
		}
	}
}

func TestCertify(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	// Inject a fake CA private key.
	f.InjectObject("ca-key-001", "PrivateKey", []string{"vault_pki_ca"}, nil, nil)

	// Fake CSR bytes (not validated by FakeKMS).
	fakePEM := []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
	resp, err := c.Certify(context.Background(), fakePEM, "ca-key-001", "", nil)
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	if resp.CertUID == "" {
		t.Fatal("Certify returned empty CertUID")
	}
}

func TestKMIPError(t *testing.T) {
	f := NewFakeKMS()
	defer f.Close()
	c := newTestClient(t, f)

	// Request a non-existent UID to trigger an error response.
	_, err := c.GetPublicKey(context.Background(), "nonexistent-uid")
	if err == nil {
		t.Fatal("expected error for non-existent UID")
	}
	var kmipErr *KMIPError
	if !isKMIPError(err, &kmipErr) {
		t.Fatalf("expected *KMIPError, got %T: %v", err, err)
	}
}

// isKMIPError unwraps err to find a *KMIPError.
func isKMIPError(err error, target **KMIPError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*KMIPError); ok {
		*target = e
		return true
	}
	// Check wrapped.
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return isKMIPError(u.Unwrap(), target)
	}
	return false
}
