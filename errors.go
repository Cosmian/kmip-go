package kmip

import "fmt"

// KMIPError is returned when the KMS responds with a KMIP OperationFailed result.
type KMIPError struct {
	ResultReason  string
	ResultMessage string
}

func (e *KMIPError) Error() string {
	if e.ResultMessage != "" {
		return fmt.Sprintf("KMIP error [%s]: %s", e.ResultReason, e.ResultMessage)
	}
	return fmt.Sprintf("KMIP error [%s]", e.ResultReason)
}

func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
