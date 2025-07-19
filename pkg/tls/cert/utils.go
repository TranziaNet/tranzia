package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

var keyUsageMap = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"keyCertSign":       x509.KeyUsageCertSign,
	"crlSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

func ParseKeyUsageStrict(input string) (x509.KeyUsage, error) {
	if input == "" {
		return 0, nil
	}
	var usage x509.KeyUsage
	for _, u := range strings.Split(input, ",") {
		u = strings.TrimSpace(u)
		val, ok := keyUsageMap[u]
		if !ok {
			return 0, fmt.Errorf("invalid key usage: %s", u)
		}
		usage |= val
	}
	return usage, nil
}

func EncodeToPem(key any, keyType string) ([]byte, error) {

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: der,
	})

	return pem, nil

}
