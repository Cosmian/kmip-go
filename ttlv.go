// Package kmip provides a minimal KMIP 2.1 JSON TTLV client for Eviden KMS.
//
// The KMS server accepts KMIP 2.1 operations as JSON TTLV posted to POST /kmip/2_1.
// Each message is either a bare operation (e.g. {"tag":"CreateKeyPair","value":[...]})
// or a full RequestMessage envelope. This package sends bare operations.
//
// JSON TTLV encoding rules (KMIP 2.1 §14.1):
//   - Every field is {"tag":"<Name>","type":"<Type>","value":<value>}
//   - Structure nodes omit "type"; their "value" is a JSON array of children.
//   - Enumeration values are their text name (e.g. "RSA", "ECDSA").
//   - ByteString values are uppercase hex strings.
//   - Integer values are JSON numbers.
//   - TextString values are JSON strings.
package kmip

import "encoding/json"

// TTLV is a single KMIP JSON TTLV node.
type TTLV struct {
	Tag   string          `json:"tag"`
	Type  string          `json:"type,omitempty"` // omitted for Structure nodes
	Value json.RawMessage `json:"value"`
}

// Structure returns a TTLV Structure node with the given tag and child nodes.
func Structure(tag string, children ...TTLV) TTLV {
	b, _ := json.Marshal(children)
	return TTLV{Tag: tag, Value: b}
}

// TextString returns a TTLV TextString node.
func TextString(tag, value string) TTLV {
	b, _ := json.Marshal(value)
	return TTLV{Tag: tag, Type: "TextString", Value: b}
}

// Enumeration returns a TTLV Enumeration node. The value is the enumeration name
// as used by Eviden KMS (e.g. "RSA", "ECDSA", "SHA256", "PKCS1v15").
func Enumeration(tag, value string) TTLV {
	b, _ := json.Marshal(value)
	return TTLV{Tag: tag, Type: "Enumeration", Value: b}
}

// Integer returns a TTLV Integer node.
func Integer(tag string, value int) TTLV {
	b, _ := json.Marshal(value)
	return TTLV{Tag: tag, Type: "Integer", Value: b}
}

// ByteString returns a TTLV ByteString node. The value must be an uppercase hex string.
func ByteString(tag, hexValue string) TTLV {
	b, _ := json.Marshal(hexValue)
	return TTLV{Tag: tag, Type: "ByteString", Value: b}
}

// DateTime returns a TTLV DateTime node. The value must be an RFC3339 string.
func DateTime(tag, rfc3339Value string) TTLV {
	b, _ := json.Marshal(rfc3339Value)
	return TTLV{Tag: tag, Type: "DateTime", Value: b}
}

// stringValue extracts the string value from a TTLV node, returning ("", false) on failure.
func stringValue(t TTLV) (string, bool) {
	var s string
	if err := json.Unmarshal(t.Value, &s); err != nil {
		return "", false
	}
	return s, true
}

// childrenOf parses the value of a Structure TTLV node into a slice of children.
func childrenOf(t TTLV) ([]TTLV, error) {
	var children []TTLV
	if err := json.Unmarshal(t.Value, &children); err != nil {
		return nil, err
	}
	return children, nil
}

// findChild returns the first child with the given tag, or (TTLV{}, false).
func findChild(children []TTLV, tag string) (TTLV, bool) {
	for _, c := range children {
		if c.Tag == tag {
			return c, true
		}
	}
	return TTLV{}, false
}

// bytesValue decodes the hex ByteString value of a TTLV node into a byte slice.
func bytesValue(t TTLV) ([]byte, bool) {
	var hex string
	if err := json.Unmarshal(t.Value, &hex); err != nil {
		return nil, false
	}
	b, err := hexDecode(hex)
	if err != nil {
		return nil, false
	}
	return b, true
}

// hexDecode converts an uppercase hex string to bytes.
func hexDecode(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		return nil, errorf("hex string has odd length: %s", h)
	}
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		hi := hexNibble(h[i])
		lo := hexNibble(h[i+1])
		if hi < 0 || lo < 0 {
			return nil, errorf("invalid hex character in: %s", h)
		}
		b[i/2] = byte(hi<<4 | lo)
	}
	return b, nil
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

// hexEncode converts bytes to an uppercase hex string.
func hexEncode(b []byte) string {
	const hextable = "0123456789ABCDEF"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}
