// Package kmip — KMIP 2.1 operation helpers.
//
// FIPS-mode usage masks for Eviden KMS:
//
//   EC  private: 0x00103A01 = 1063425  (Sign|CertSign|CRLSign|Auth|DeriveKey|KeyAgreement)
//   EC  public:  0x00100A02 = 1051138  (Verify|Auth|DeriveKey|KeyAgreement)
//   RSA private: 0x00000A29 = 2601     (Sign|Decrypt|UnwrapKey|DeriveKey|KeyAgreement)
//   RSA public:  0x00000A16 = 2582     (Verify|Encrypt|WrapKey|DeriveKey|KeyAgreement)

package kmip

import (
	"context"
	"fmt"
	"strings"
)

// VendorIDCosmian is the vendor identification string used by Eviden KMS for
// custom attributes.
const VendorIDCosmian = "cosmian"

// AttrNameTag is the attribute name used for KMS object tags.
const AttrNameTag = "tag"

// ────────────────────────────────────────────────────────────────────────────
// Key types
// ────────────────────────────────────────────────────────────────────────────

// KeyType represents the KMIP key type for key creation.
type KeyType string

const (
	KeyTypeECP256  KeyType = "EC_P256"
	KeyTypeECP384  KeyType = "EC_P384"
	KeyTypeRSA2048 KeyType = "RSA_2048"
	KeyTypeRSA4096 KeyType = "RSA_4096"
)

// FIPS-compliant CryptographicUsageMask values for each key kind.
const (
	fipsECPrivateMask  = 1063425 // 0x00103A01
	fipsECPublicMask   = 1051138 // 0x00100A02
	fipsRSAPrivateMask = 2601    // 0x00000A29
	fipsRSAPublicMask  = 2582    // 0x00000A16
)

// ────────────────────────────────────────────────────────────────────────────
// CreateKeyPair
// ────────────────────────────────────────────────────────────────────────────

// CreateKeyPairResponse contains the UIDs returned by CreateKeyPair.
type CreateKeyPairResponse struct {
	// PrivateKeyUID is the KMIP UniqueIdentifier of the created private key.
	PrivateKeyUID string
	// PublicKeyUID is the KMIP UniqueIdentifier of the created public key.
	PublicKeyUID string
}

// CreateKeyPair creates an asymmetric key pair in the KMS.
// tags is the set of KMS vendor tags to attach to the key (used for discovery).
func (c *Client) CreateKeyPair(ctx context.Context, kt KeyType, tags []string) (*CreateKeyPairResponse, error) {
	var req TTLV

	switch kt {
	case KeyTypeECP256, KeyTypeECP384:
		curve := "P256"
		if kt == KeyTypeECP384 {
			curve = "P384"
		}
		commonAttrs := []TTLV{
			Enumeration("CryptographicAlgorithm", "EC"),
			Structure("CryptographicDomainParameters",
				Enumeration("RecommendedCurve", curve),
			),
			Enumeration("KeyFormatType", "ECPrivateKey"),
			DateTime("ActivationDate", "2024-01-01T00:00:00Z"),
		}
		if len(tags) > 0 {
			commonAttrs = append(commonAttrs, vendorTagAttr(tags))
		}
		req = Structure("CreateKeyPair",
			Structure("CommonAttributes", commonAttrs...),
			Structure("PrivateKeyAttributes",
				Integer("CryptographicUsageMask", fipsECPrivateMask),
			),
			Structure("PublicKeyAttributes",
				Integer("CryptographicUsageMask", fipsECPublicMask),
			),
		)

	case KeyTypeRSA2048, KeyTypeRSA4096:
		length := 2048
		if kt == KeyTypeRSA4096 {
			length = 4096
		}
		commonAttrs := []TTLV{
			Enumeration("CryptographicAlgorithm", "RSA"),
			Integer("CryptographicLength", length),
			Enumeration("KeyFormatType", "TransparentRSAPrivateKey"),
			DateTime("ActivationDate", "2024-01-01T00:00:00Z"),
		}
		if len(tags) > 0 {
			commonAttrs = append(commonAttrs, vendorTagAttr(tags))
		}
		req = Structure("CreateKeyPair",
			Structure("CommonAttributes", commonAttrs...),
			Structure("PrivateKeyAttributes",
				Integer("CryptographicUsageMask", fipsRSAPrivateMask),
			),
			Structure("PublicKeyAttributes",
				Integer("CryptographicUsageMask", fipsRSAPublicMask),
			),
		)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("CreateKeyPair: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return nil, fmt.Errorf("CreateKeyPair: parse response: %w", err)
	}

	var result CreateKeyPairResponse
	for _, child := range children {
		switch child.Tag {
		case "PrivateKeyUniqueIdentifier":
			if s, ok := stringValue(child); ok {
				result.PrivateKeyUID = s
			}
		case "PublicKeyUniqueIdentifier":
			if s, ok := stringValue(child); ok {
				result.PublicKeyUID = s
			}
		}
	}
	if result.PrivateKeyUID == "" || result.PublicKeyUID == "" {
		return nil, fmt.Errorf("CreateKeyPair: missing UIDs in response")
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// GetPublicKey — Get DER-encoded PKIX public key from the public key object
// ────────────────────────────────────────────────────────────────────────────

// GetPublicKeyResponse contains the PKIX public key bytes.
type GetPublicKeyResponse struct {
	// PublicKeyPKIX is the DER-encoded SubjectPublicKeyInfo.
	PublicKeyPKIX []byte
}

// GetPublicKey fetches the DER-encoded PKIX public key for a given **public key** UID.
// Pass CreateKeyPairResponse.PublicKeyUID, not the private key UID.
func (c *Client) GetPublicKey(ctx context.Context, publicKeyUID string) (*GetPublicKeyResponse, error) {
	req := Structure("Get",
		TextString("UniqueIdentifier", publicKeyUID),
		Enumeration("KeyFormatType", "PKCS8"),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKey: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKey: parse response: %w", err)
	}

	// Path: GetResponse → PublicKey → KeyBlock → KeyValue → KeyMaterial (ByteString)
	for _, child := range children {
		if child.Tag == "PublicKey" {
			pkChildren, _ := childrenOf(child)
			for _, pkc := range pkChildren {
				if pkc.Tag == "KeyBlock" {
					kbChildren, _ := childrenOf(pkc)
					for _, kbc := range kbChildren {
						if kbc.Tag == "KeyValue" {
							kvChildren, _ := childrenOf(kbc)
							for _, kvc := range kvChildren {
								if kvc.Tag == "KeyMaterial" {
									if b, ok := bytesValue(kvc); ok {
										return &GetPublicKeyResponse{PublicKeyPKIX: b}, nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("GetPublicKey: PKIX key material not found in response for uid %s", publicKeyUID)
}

// ────────────────────────────────────────────────────────────────────────────
// Locate
// ────────────────────────────────────────────────────────────────────────────

// Locate returns the UIDs of all private keys matching the given vendor tags.
func (c *Client) Locate(ctx context.Context, tags []string) ([]string, error) {
	attrs := []TTLV{
		Enumeration("ObjectType", "PrivateKey"),
	}
	if len(tags) > 0 {
		attrs = append(attrs, vendorTagAttr(tags))
	}
	req := Structure("Locate",
		Structure("Attributes", attrs...),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Locate: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return nil, fmt.Errorf("Locate: parse response: %w", err)
	}

	var uids []string
	for _, child := range children {
		if child.Tag == "UniqueIdentifier" {
			if s, ok := stringValue(child); ok {
				uids = append(uids, s)
			}
		}
	}
	return uids, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Sign
// ────────────────────────────────────────────────────────────────────────────

// HashAlgorithm names supported by Eviden KMS Sign.
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "SHA256"
	HashSHA384 HashAlgorithm = "SHA384"
	HashSHA512 HashAlgorithm = "SHA512"
)

// SignatureAlgorithm names supported by Eviden KMS Sign.
type SignatureAlgorithm string

const (
	SigECDSA    SignatureAlgorithm = "ECDSA"
	SigRSAPKCS1 SignatureAlgorithm = "RSASSA_PKCS1_v1_5"
	SigRSAPSS   SignatureAlgorithm = "RSASSA_PSS"
)

// kmipDigitalSignatureAlgorithm maps (hash, sig) to the KMIP DigitalSignatureAlgorithm name.
func kmipDigitalSignatureAlgorithm(hash HashAlgorithm, sig SignatureAlgorithm) (string, error) {
	switch sig {
	case SigECDSA:
		switch hash {
		case HashSHA256:
			return "ECDSAWithSHA256", nil
		case HashSHA384:
			return "ECDSAWithSHA384", nil
		case HashSHA512:
			return "ECDSAWithSHA512", nil
		}
	case SigRSAPKCS1:
		switch hash {
		case HashSHA256:
			return "SHA256WithRSAEncryption", nil
		case HashSHA384:
			return "SHA384WithRSAEncryption", nil
		case HashSHA512:
			return "SHA512WithRSAEncryption", nil
		}
	case SigRSAPSS:
		return "RSASSAPSS", nil
	}
	return "", fmt.Errorf("unsupported (hash=%s, sig=%s) combination", hash, sig)
}

// Sign signs pre-hashed data with the private key identified by uid.
// data must be the raw digest bytes (the KMS will not re-hash them).
func (c *Client) Sign(ctx context.Context, uid string, data []byte, hash HashAlgorithm, sig SignatureAlgorithm) ([]byte, error) {
	dsaAlgo, err := kmipDigitalSignatureAlgorithm(hash, sig)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}

	cryptoParams := []TTLV{
		Enumeration("HashingAlgorithm", string(hash)),
		Enumeration("DigitalSignatureAlgorithm", dsaAlgo),
	}
	if sig == SigRSAPSS {
		cryptoParams = append(cryptoParams, Enumeration("PaddingMethod", "PSS"))
	}

	req := Structure("Sign",
		TextString("UniqueIdentifier", uid),
		Structure("CryptographicParameters", cryptoParams...),
		// DigestedData = pre-hashed input (the KMS does NOT re-hash)
		ByteString("DigestedData", hexEncode(data)),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return nil, fmt.Errorf("Sign: parse response: %w", err)
	}

	for _, child := range children {
		if child.Tag == "SignatureData" {
			if b, ok := bytesValue(child); ok {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("Sign: SignatureData not found in response")
}

// ────────────────────────────────────────────────────────────────────────────
// Destroy
// ────────────────────────────────────────────────────────────────────────────

// Destroy destroys the managed object identified by uid.
// Per KMIP lifecycle rules, Active objects must be Revoked before Destroy.
// This function revokes first (CessationOfOperation), then destroys.
func (c *Client) Destroy(ctx context.Context, uid string) error {
	// Revoke first to move the object to Deactivated/Compromised state.
	revokeReq := Structure("Revoke",
		TextString("UniqueIdentifier", uid),
		Structure("RevocationReason",
			Enumeration("RevocationReasonCode", "CessationOfOperation"),
		),
	)
	// Ignore revoke errors — the object may already be in a deactivated state.
	_, _ = c.Do(ctx, revokeReq)

	destroyReq := Structure("Destroy",
		TextString("UniqueIdentifier", uid),
	)
	_, err := c.Do(ctx, destroyReq)
	if err != nil {
		return fmt.Errorf("Destroy %s: %w", uid, err)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Certify
// ────────────────────────────────────────────────────────────────────────────

// CertifyResponse contains the results of a Certify operation.
type CertifyResponse struct {
	// CertUID is the KMIP UniqueIdentifier of the newly signed certificate.
	CertUID string
}

// Certify signs a PEM-encoded CSR using the specified CA private key.
// caCertUID is the KMIP UID of the issuing CA certificate; it is required because
// the KMS needs to identify the issuer certificate to build the chain.
// x509Extension is an optional OpenSSL-format extension file content (e.g.
// "[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"). Pass nil for no extension.
//
// Note: the Eviden KMS Certify operation does not accept a standalone validity period
// on CSR-based requests; the signed certificate TTL is controlled by the KMS server
// configuration. SPIRE's PreferredTtl hint is acknowledged but not forwarded.
func (c *Client) Certify(ctx context.Context, csrPEM []byte, caKeyUID, caCertUID string, x509Extension []byte) (*CertifyResponse, error) {
	attrs := []TTLV{
		Structure("Link",
			Enumeration("LinkType", "PrivateKeyLink"),
			TextString("LinkedObjectIdentifier", caKeyUID),
		),
	}
	if caCertUID != "" {
		attrs = append(attrs, Structure("Link",
			Enumeration("LinkType", "CertificateLink"),
			TextString("LinkedObjectIdentifier", caCertUID),
		))
	}
	if len(x509Extension) > 0 {
		// Set the X.509 extension as a cosmian vendor attribute (ByteString).
		attrs = append(attrs, Structure("Attribute",
			TextString("VendorIdentification", VendorIDCosmian),
			TextString("AttributeName", "x509-extension"),
			ByteString("AttributeValue", hexEncode(x509Extension)),
		))
	}

	req := Structure("Certify",
		Enumeration("CertificateRequestType", "PEM"),
		ByteString("CertificateRequestValue", hexEncode(csrPEM)),
		Structure("Attributes", attrs...),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Certify: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return nil, fmt.Errorf("Certify: parse response: %w", err)
	}

	for _, child := range children {
		if child.Tag == "UniqueIdentifier" {
			if uid, ok := stringValue(child); ok {
				return &CertifyResponse{CertUID: uid}, nil
			}
		}
	}
	return nil, fmt.Errorf("Certify: UniqueIdentifier not found in response")
}

// ────────────────────────────────────────────────────────────────────────────
// ExportCertificate
// ────────────────────────────────────────────────────────────────────────────

// ExportCertificate retrieves the PEM-encoded certificate for the given UID.
func (c *Client) ExportCertificate(ctx context.Context, certUID string) ([]byte, error) {
	req := Structure("Get",
		TextString("UniqueIdentifier", certUID),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Get certificate %s: %w", certUID, err)
	}

	// Path: GetResponse → Certificate → CertificateValue (ByteString)
	children, err := childrenOf(resp)
	if err != nil {
		return nil, fmt.Errorf("Get: parse response: %w", err)
	}

	for _, child := range children {
		if child.Tag == "Certificate" {
			certChildren, _ := childrenOf(child)
			for _, cc := range certChildren {
				if cc.Tag == "CertificateValue" {
					if b, ok := bytesValue(cc); ok {
						return b, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("Get: certificate value not found in response for uid %s", certUID)
}

// ────────────────────────────────────────────────────────────────────────────
// AddTags
// ────────────────────────────────────────────────────────────────────────────

// AddTags adds vendor tags to an existing KMS object identified by uid.
func (c *Client) AddTags(ctx context.Context, uid string, tags []string) error {
	req := Structure("SetAttribute",
		TextString("UniqueIdentifier", uid),
		Structure("Attribute", vendorTagAttrChildren(tags)...),
	)
	_, err := c.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("SetAttribute tags on %s: %w", uid, err)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

// vendorTagAttr builds a KMIP Attribute Structure encoding a cosmian tag set.
// Tag values are JSON-encoded as a JSON array of strings, matching the KMS internal format.
func vendorTagAttr(tags []string) TTLV {
	return Structure("Attribute", vendorTagAttrChildren(tags)...)
}

func vendorTagAttrChildren(tags []string) []TTLV {
	quoted := make([]string, len(tags))
	for i, t := range tags {
		quoted[i] = `"` + t + `"`
	}
	tagJSON := "[" + strings.Join(quoted, ",") + "]"
	return []TTLV{
		TextString("VendorIdentification", VendorIDCosmian),
		TextString("AttributeName", AttrNameTag),
		TextString("AttributeValue", tagJSON),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// GetLinkedPublicKeyUID — resolve public key UID from private key attributes
// ────────────────────────────────────────────────────────────────────────────

// GetLinkedPublicKeyUID retrieves the public key UID linked to the given private key UID
// by reading the PublicKeyLink attribute from the private key's GetAttributes response.
func (c *Client) GetLinkedPublicKeyUID(ctx context.Context, privateKeyUID string) (string, error) {
	req := Structure("GetAttributes",
		TextString("UniqueIdentifier", privateKeyUID),
		TextString("AttributeName", "Link"),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("GetLinkedPublicKeyUID: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return "", fmt.Errorf("GetLinkedPublicKeyUID: parse response: %w", err)
	}

	for _, child := range children {
		if child.Tag == "Attributes" {
			attrs, _ := childrenOf(child)
			for _, attr := range attrs {
				if attr.Tag == "Link" {
					linkChildren, _ := childrenOf(attr)
					linkType, linkedUID := "", ""
					for _, lc := range linkChildren {
						switch lc.Tag {
						case "LinkType":
							linkType, _ = stringValue(lc)
						case "LinkedObjectIdentifier":
							linkedUID, _ = stringValue(lc)
						}
					}
					if linkType == "PublicKeyLink" && linkedUID != "" {
						return linkedUID, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("GetLinkedPublicKeyUID: PublicKeyLink not found for private key %s", privateKeyUID)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateSelfSignedCertificate
// ────────────────────────────────────────────────────────────────────────────

// CAExtension is the X.509 extension file content for a CA certificate.
// Sets basicConstraints=critical,CA:TRUE and the appropriate key usages.
// Pass this to CreateSelfSignedCertificate and Certify when creating CA certificates
// that will sign other certificates (e.g. SPIRE intermediate CAs).
var CAExtension = []byte("[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,crlSign,digitalSignature\n")

// CreateSelfSignedCertificate creates a self-signed X.509 certificate for the
// given public key UID. The KMS finds the corresponding private key via the
// PublicKeyLink stored on the public key object.
//
// subjectCN is the certificate Common Name (e.g. "My Root CA").
// x509Extension sets optional X.509 extensions (use CAExtension for CA certs). Pass nil for no extension.
// Returns the UID of the created certificate object.
func (c *Client) CreateSelfSignedCertificate(ctx context.Context, publicKeyUID, subjectCN string, x509Extension []byte) (string, error) {
	attrs := []TTLV{
		Enumeration("CertificateType", "X509"),
		Structure("CertificateAttributes",
			TextString("CertificateSubjectCn", subjectCN),
			TextString("CertificateSubjectO", ""),
			TextString("CertificateSubjectOu", ""),
			TextString("CertificateSubjectEmail", ""),
			TextString("CertificateSubjectC", ""),
			TextString("CertificateSubjectSt", ""),
			TextString("CertificateSubjectL", ""),
			TextString("CertificateSubjectUid", ""),
			TextString("CertificateSubjectSerialNumber", ""),
			TextString("CertificateSubjectTitle", ""),
			TextString("CertificateSubjectDc", ""),
			TextString("CertificateSubjectDnQualifier", ""),
			TextString("CertificateIssuerCn", ""),
			TextString("CertificateIssuerO", ""),
			TextString("CertificateIssuerOu", ""),
			TextString("CertificateIssuerEmail", ""),
			TextString("CertificateIssuerC", ""),
			TextString("CertificateIssuerSt", ""),
			TextString("CertificateIssuerL", ""),
			TextString("CertificateIssuerUid", ""),
			TextString("CertificateIssuerSerialNumber", ""),
			TextString("CertificateIssuerTitle", ""),
			TextString("CertificateIssuerDc", ""),
			TextString("CertificateIssuerDnQualifier", ""),
		),
	}
	if len(x509Extension) > 0 {
		attrs = append(attrs, Structure("Attribute",
			TextString("VendorIdentification", VendorIDCosmian),
			TextString("AttributeName", "x509-extension"),
			ByteString("AttributeValue", hexEncode(x509Extension)),
		))
	}

	req := Structure("Certify",
		TextString("UniqueIdentifier", publicKeyUID),
		Structure("Attributes", attrs...),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("CreateSelfSignedCertificate: %w", err)
	}

	children, err := childrenOf(resp)
	if err != nil {
		return "", fmt.Errorf("CreateSelfSignedCertificate: parse response: %w", err)
	}

	for _, child := range children {
		if child.Tag == "UniqueIdentifier" {
			if uid, ok := stringValue(child); ok {
				return uid, nil
			}
		}
	}
	return "", fmt.Errorf("CreateSelfSignedCertificate: UniqueIdentifier not found in response")
}

// ────────────────────────────────────────────────────────────────────────────
// GetLinkedCertificateUID — find the certificate linked to a private key
// ────────────────────────────────────────────────────────────────────────────

// GetLinkedCertificateUID retrieves the CertificateLink UID associated with a private key.
//
// The lookup follows the same two-step logic as the KMS server itself:
//  1. Check for a direct CertificateLink or PKCS12CertificateLink on the private key.
//  2. If not found, follow the PublicKeyLink to the public key and check there.
//
// The CertificateLink is set on the public key when CreateSelfSignedCertificate is called.
func (c *Client) GetLinkedCertificateUID(ctx context.Context, privateKeyUID string) (string, error) {
	// Step 1: look for CertificateLink directly on the private key.
	if uid, err := c.getFirstLinkUID(ctx, privateKeyUID, "CertificateLink", "PKCS12CertificateLink"); err == nil {
		return uid, nil
	}

	// Step 2: follow the PublicKeyLink to the public key, then look there.
	pubKeyUID, err := c.getFirstLinkUID(ctx, privateKeyUID, "PublicKeyLink")
	if err != nil {
		return "", fmt.Errorf("GetLinkedCertificateUID: no PublicKeyLink on private key %s: %w", privateKeyUID, err)
	}
	certUID, err := c.getFirstLinkUID(ctx, pubKeyUID, "CertificateLink", "PKCS12CertificateLink")
	if err != nil {
		return "", fmt.Errorf("GetLinkedCertificateUID: no CertificateLink found on private key %s or its public key %s (create a self-signed cert first with CreateSelfSignedCertificate)", privateKeyUID, pubKeyUID)
	}
	return certUID, nil
}

// getFirstLinkUID returns the LinkedObjectIdentifier of the first Link attribute with
// one of the specified LinkType names, fetched via GetAttributes on the given object UID.
func (c *Client) getFirstLinkUID(ctx context.Context, uid string, linkTypes ...string) (string, error) {
	req := Structure("GetAttributes",
		TextString("UniqueIdentifier", uid),
		TextString("AttributeName", "Link"),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return "", err
	}

	children, err := childrenOf(resp)
	if err != nil {
		return "", err
	}

	wantTypes := make(map[string]struct{}, len(linkTypes))
	for _, lt := range linkTypes {
		wantTypes[lt] = struct{}{}
	}

	for _, child := range children {
		if child.Tag == "Attributes" {
			attrs, _ := childrenOf(child)
			for _, attr := range attrs {
				if attr.Tag == "Link" {
					linkChildren, _ := childrenOf(attr)
					linkType, linkedUID := "", ""
					for _, lc := range linkChildren {
						switch lc.Tag {
						case "LinkType":
							linkType, _ = stringValue(lc)
						case "LinkedObjectIdentifier":
							linkedUID, _ = stringValue(lc)
						}
					}
					if _, ok := wantTypes[linkType]; ok && linkedUID != "" {
						return linkedUID, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("no matching link found on object %s", uid)
}

// ────────────────────────────────────────────────────────────────────────────
// GetVendorTags — read the cosmian tag array from a KMS object's attributes
// ────────────────────────────────────────────────────────────────────────────

// GetVendorTags returns the cosmian vendor tags stored on the object identified
// by uid. Returns an empty slice if no tags are set.
func (c *Client) GetVendorTags(ctx context.Context, uid string) ([]string, error) {
	req := Structure("GetAttributes",
		TextString("UniqueIdentifier", uid),
		TextString("AttributeName", "Attribute"),
	)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetVendorTags: %w", err)
	}

	return extractTagsFromResponse(resp), nil
}

// extractTagsFromResponse walks the GetAttributes response and returns cosmian tags.
func extractTagsFromResponse(resp TTLV) []string {
	return extractTagsFromTTLV_op(resp)
}

func extractTagsFromTTLV_op(node TTLV) []string {
	children, err := childrenOf(node)
	if err != nil {
		return nil
	}
	if node.Tag == "Attribute" {
		vendorID, attrName, attrValue := "", "", ""
		for _, c := range children {
			switch c.Tag {
			case "VendorIdentification":
				vendorID, _ = stringValue(c)
			case "AttributeName":
				attrName, _ = stringValue(c)
			case "AttributeValue":
				attrValue, _ = stringValue(c)
			}
		}
		if vendorID == VendorIDCosmian && attrName == AttrNameTag && attrValue != "" {
			return parseTagJSON(attrValue)
		}
	}
	for _, child := range children {
		if tags := extractTagsFromTTLV_op(child); len(tags) > 0 {
			return tags
		}
	}
	return nil
}
