// Package kmip — fake KMS HTTP server for testing.
//
// FakeKMS is an in-process httptest.Server that accepts KMIP 2.1 JSON TTLV requests
// to POST /kmip/2_1 and returns canned responses. It is exported so that SPIRE plugin
// tests can import and use it directly.

package kmip

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// FakeKMS is an in-process KMIP test server.
//
// It maintains an in-memory store of keys and certificates, handles the KMIP
// operations needed by the KeyManager and UpstreamAuthority plugins, and records
// every request for assertion in tests.
type FakeKMS struct {
	mu       sync.Mutex
	server   *httptest.Server
	store    map[string]*fakeObject // uid → object
	requests []TTLV                 // recorded for assertion

	// tlsCert is the server TLS certificate.
	tlsCert tls.Certificate
}

type fakeObject struct {
	uid     string
	typ     string // "PrivateKey", "Certificate", etc.
	tags    []string
	pkix    []byte // DER-encoded SubjectPublicKeyInfo (for key objects)
	certPEM []byte // PEM-encoded certificate (for certificate objects)
}

// NewFakeKMS starts and returns a new FakeKMS that listens on localhost.
// Close it with Close().
func NewFakeKMS() *FakeKMS {
	f := &FakeKMS{
		store: make(map[string]*fakeObject),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/kmip/2_1", f.handleKMIP)
	f.server = httptest.NewServer(mux)
	return f
}

// URL returns the base URL of the fake server (e.g. "http://127.0.0.1:PORT").
func (f *FakeKMS) URL() string {
	return f.server.URL
}

// Close stops the fake server.
func (f *FakeKMS) Close() {
	f.server.Close()
}

// Requests returns a copy of all KMIP requests received so far.
func (f *FakeKMS) Requests() []TTLV {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]TTLV, len(f.requests))
	copy(cp, f.requests)
	return cp
}

// InjectObject pre-populates the store with an object (used for CA key tests).
func (f *FakeKMS) InjectObject(uid, typ string, tags []string, pkix []byte, certPEM []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[uid] = &fakeObject{uid: uid, typ: typ, tags: tags, pkix: pkix, certPEM: certPEM}
}

// handleKMIP is the HTTP handler for POST /kmip/2_1.
func (f *FakeKMS) handleKMIP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var req TTLV
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "parse TTLV: "+err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	var resp TTLV
	switch req.Tag {
	case "CreateKeyPair":
		resp = f.handleCreateKeyPair(req)
	case "GetAttributes":
		resp = f.handleGetAttributes(req)
	case "Locate":
		resp = f.handleLocate(req)
	case "Sign":
		resp = f.handleSign(req)
	case "Revoke":
		resp = f.handleRevoke(req)
	case "Destroy":
		resp = f.handleDestroy(req)
	case "Certify":
		resp = f.handleCertify(req)
	case "Get":
		resp = f.handleGet(req)
	case "SetAttribute":
		resp = f.handleSetAttribute(req)
	default:
		resp = errorResponse(fmt.Sprintf("unsupported operation: %s", req.Tag))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ────────────────────────────────────────────────────────────────────────────
// Operation handlers
// ────────────────────────────────────────────────────────────────────────────

func (f *FakeKMS) handleCreateKeyPair(req TTLV) TTLV {
	// Generate a minimal RSA 2048 key pair.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errorResponse("generate key: " + err.Error())
	}

	pkix, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return errorResponse("marshal public key: " + err.Error())
	}

	privUID := newUID()
	pubUID := privUID + "_pk"

	tags := extractTagsFromRequest(req)

	f.mu.Lock()
	f.store[privUID] = &fakeObject{uid: privUID, typ: "PrivateKey", tags: tags, pkix: pkix}
	f.store[pubUID] = &fakeObject{uid: pubUID, typ: "PublicKey", tags: tags, pkix: pkix}
	f.mu.Unlock()

	return Structure("CreateKeyPairResponse",
		TextString("PrivateKeyUniqueIdentifier", privUID),
		TextString("PublicKeyUniqueIdentifier", pubUID),
	)
}

func (f *FakeKMS) handleGetAttributes(req TTLV) TTLV {
	children, _ := childrenOf(req)
	uid := ""
	if c, ok := findChild(children, "UniqueIdentifier"); ok {
		uid, _ = stringValue(c)
	}
	attrName := ""
	if c, ok := findChild(children, "AttributeName"); ok {
		attrName, _ = stringValue(c)
	}

	f.mu.Lock()
	obj, ok := f.store[uid]
	f.mu.Unlock()

	if !ok {
		return errorResponse(fmt.Sprintf("object not found: %s", uid))
	}

	attrs := []TTLV{}

	wantLinks := attrName == "Link" || attrName == ""
	wantTags := attrName == "Attribute" || attrName == ""
	wantPKIX := attrName == "PKIXPublicKey"

	if wantLinks {
		if obj.typ == "PrivateKey" {
			pubUID := uid + "_pk"
			attrs = append(attrs, Structure("Link",
				Enumeration("LinkType", "PublicKeyLink"),
				TextString("LinkedObjectIdentifier", pubUID),
			))
		} else if obj.typ == "PublicKey" {
			certUID := uid[:len(uid)-3] + "_cert"
			if _, exists := f.store[certUID]; exists {
				attrs = append(attrs, Structure("Link",
					Enumeration("LinkType", "CertificateLink"),
					TextString("LinkedObjectIdentifier", certUID),
				))
			}
		}
	}

	if wantTags && len(obj.tags) > 0 {
		attrs = append(attrs, vendorTagAttr(obj.tags))
	}

	if wantPKIX && len(obj.pkix) > 0 {
		attrs = append(attrs, ByteString("PKIXPublicKey", hexEncode(obj.pkix)))
	}

	return Structure("GetAttributesResponse",
		TextString("UniqueIdentifier", uid),
		Structure("Attributes", attrs...),
	)
}

func (f *FakeKMS) handleLocate(req TTLV) TTLV {
	// Find all private keys whose tags contain all requested tags.
	reqTags := extractTagsFromRequest(req)

	f.mu.Lock()
	defer f.mu.Unlock()

	var uids []TTLV
	for uid, obj := range f.store {
		if obj.typ != "PrivateKey" {
			continue
		}
		if tagsMatch(obj.tags, reqTags) {
			uids = append(uids, TextString("UniqueIdentifier", uid))
		}
	}

	return Structure("LocateResponse", uids...)
}

func (f *FakeKMS) handleSign(_ TTLV) TTLV {
	// Return a fake 64-byte signature.
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)
	return Structure("SignResponse",
		ByteString("SignatureData", hexEncode(sig)),
	)
}

func (f *FakeKMS) handleRevoke(req TTLV) TTLV {
	children, _ := childrenOf(req)
	uid := ""
	if c, ok := findChild(children, "UniqueIdentifier"); ok {
		uid, _ = stringValue(c)
	}
	return Structure("RevokeResponse",
		TextString("UniqueIdentifier", uid),
	)
}

func (f *FakeKMS) handleDestroy(req TTLV) TTLV {
	children, _ := childrenOf(req)
	uid := ""
	if c, ok := findChild(children, "UniqueIdentifier"); ok {
		uid, _ = stringValue(c)
	}

	f.mu.Lock()
	delete(f.store, uid)
	f.mu.Unlock()

	return Structure("DestroyResponse",
		TextString("UniqueIdentifier", uid),
	)
}

func (f *FakeKMS) handleCertify(req TTLV) TTLV {
	// Generate a self-signed certificate as a stand-in for the signed intermediate.
	certUID := newUID()
	certPEM := fakeCertPEM()

	f.mu.Lock()
	f.store[certUID] = &fakeObject{uid: certUID, typ: "Certificate", certPEM: []byte(certPEM)}
	f.mu.Unlock()

	_ = req // CSR bytes are not validated in the fake

	return Structure("CertifyResponse",
		TextString("UniqueIdentifier", certUID),
	)
}

func (f *FakeKMS) handleGet(req TTLV) TTLV {
	children, _ := childrenOf(req)
	uid := ""
	if c, ok := findChild(children, "UniqueIdentifier"); ok {
		uid, _ = stringValue(c)
	}

	f.mu.Lock()
	obj, ok := f.store[uid]
	f.mu.Unlock()

	if !ok {
		return errorResponse(fmt.Sprintf("object not found: %s", uid))
	}

	if obj.typ == "Certificate" {
		// Return: GetResponse → Certificate → CertificateValue
		return Structure("GetResponse",
			TextString("ObjectType", obj.typ),
			TextString("UniqueIdentifier", uid),
			Structure("Certificate",
				Enumeration("CertificateType", "X509"),
				ByteString("CertificateValue", hexEncode(obj.certPEM)),
			),
		)
	}

	// Public key: return PKCS8-encoded DER in GetResponse → PublicKey → KeyBlock → KeyValue → KeyMaterial
	return Structure("GetResponse",
		TextString("ObjectType", obj.typ),
		TextString("UniqueIdentifier", uid),
		Structure("PublicKey",
			Structure("KeyBlock",
				Enumeration("KeyFormatType", "PKCS8"),
				Structure("KeyValue",
					ByteString("KeyMaterial", hexEncode(obj.pkix)),
				),
			),
		),
	)
}

func (f *FakeKMS) handleSetAttribute(req TTLV) TTLV {
	children, _ := childrenOf(req)
	uid := ""
	if c, ok := findChild(children, "UniqueIdentifier"); ok {
		uid, _ = stringValue(c)
	}

	newTags := extractTagsFromRequest(req)

	f.mu.Lock()
	if obj, ok := f.store[uid]; ok {
		obj.tags = append(obj.tags, newTags...)
	}
	f.mu.Unlock()

	return Structure("SetAttributeResponse",
		TextString("UniqueIdentifier", uid),
	)
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func errorResponse(msg string) TTLV {
	return Structure("ErrorResponse",
		TextString("ResultStatus", "OperationFailed"),
		TextString("ResultReason", "GeneralFailure"),
		TextString("ResultMessage", msg),
	)
}

// extractTagsFromRequest walks the request TTLV tree to find a VendorAttribute
// with vendor_identification="cosmian" and attribute_name="tag", then parses the
// JSON array of tag strings from the attribute value.
func extractTagsFromRequest(req TTLV) []string {
	return extractTagsFromTTLV(req)
}

func extractTagsFromTTLV(node TTLV) []string {
	children, err := childrenOf(node)
	if err != nil {
		return nil
	}

	// Is this an Attribute structure with our vendor tag?
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

	// Recurse into children.
	for _, child := range children {
		if tags := extractTagsFromTTLV(child); len(tags) > 0 {
			return tags
		}
	}
	return nil
}

// parseTagJSON parses a JSON array string like `["tag1","tag2"]` into a []string.
func parseTagJSON(s string) []string {
	var tags []string
	_ = json.Unmarshal([]byte(s), &tags)
	return tags
}

// tagsMatch returns true if obj contains all of the required tags.
func tagsMatch(objTags, reqTags []string) bool {
	if len(reqTags) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(objTags))
	for _, t := range objTags {
		set[t] = struct{}{}
	}
	for _, t := range reqTags {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}

// newUID generates a simple sequential UID for test objects.
var uidCounter int

func newUID() string {
	uidCounter++
	return fmt.Sprintf("fake-uid-%04d", uidCounter)
}

// fakeCertPEM returns a minimal self-signed certificate PEM for testing.
func fakeCertPEM() string {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	var sb strings.Builder
	_ = pem.Encode(&sb, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return sb.String()
}
