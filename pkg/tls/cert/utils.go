package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

type CertInfo struct {
	Subject struct {
		CommonName         string   `json:"commonName,omitempty"`
		Organization       []string `json:"organization,omitempty"`
		OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
		Country            []string `json:"country,omitempty"`
		Locality           []string `json:"locality,omitempty"`
		Province           []string `json:"province,omitempty"`
	} `json:"subject"`

	Issuer struct {
		CommonName         string   `json:"commonName,omitempty"`
		Organization       []string `json:"organization,omitempty"`
		OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
		Country            []string `json:"country,omitempty"`
		Locality           []string `json:"locality,omitempty"`
		Province           []string `json:"province,omitempty"`
	} `json:"issuer"`

	SerialNumber   string   `json:"serialNumber"`
	NotBefore      string   `json:"notBefore"`
	NotAfter       string   `json:"notAfter"`
	IsCA           bool     `json:"isCA"`
	PublicKey      string   `json:"publicKey"`
	KeyUsage       []string `json:"keyUsage,omitempty"`
	ExtKeyUsage    []string `json:"extendedKeyUsage,omitempty"`
	DNSNames       []string `json:"dnsNames,omitempty"`
	EmailAddresses []string `json:"emails,omitempty"`
	IPAddresses    []string `json:"ipAddresses,omitempty"`
}

func (c *CertInfo) ExtractCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{}

	// Subject
	info.Subject.CommonName = cert.Subject.CommonName
	info.Subject.Organization = cert.Subject.Organization
	info.Subject.OrganizationalUnit = cert.Subject.OrganizationalUnit
	info.Subject.Country = cert.Subject.Country
	info.Subject.Locality = cert.Subject.Locality
	info.Subject.Province = cert.Subject.Province

	// Issuer
	info.Issuer.CommonName = cert.Issuer.CommonName
	info.Issuer.Organization = cert.Issuer.Organization
	info.Issuer.OrganizationalUnit = cert.Issuer.OrganizationalUnit
	info.Issuer.Country = cert.Issuer.Country
	info.Issuer.Locality = cert.Issuer.Locality
	info.Issuer.Province = cert.Issuer.Province

	info.SerialNumber = cert.SerialNumber.String()
	info.NotBefore = cert.NotBefore.Format(time.RFC3339)
	info.NotAfter = cert.NotAfter.Format(time.RFC3339)
	info.IsCA = cert.IsCA

	// Public Key
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKey = fmt.Sprintf("RSA (%d bits)", pub.Size()*8)
	case *ecdsa.PublicKey:
		info.PublicKey = fmt.Sprintf("ECDSA (%d bits)", pub.Curve.Params().BitSize)
	case ed25519.PublicKey:
		info.PublicKey = fmt.Sprintf("Ed25519 (%d bits)", len(pub)*8)
	default:
		info.PublicKey = "Unknown"
	}

	// Usage
	info.KeyUsage = decodeKeyUsage(cert.KeyUsage)
	info.ExtKeyUsage = decodeExtKeyUsage(cert.ExtKeyUsage)

	info.DNSNames = cert.DNSNames
	info.EmailAddresses = cert.EmailAddresses
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	return info
}

func decodeKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	return usages
}

func decodeExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range ekus {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", u))
		}
	}
	return usages
}

func ParseKeyUsageStrict(usageStr string) (x509.KeyUsage, error) {
	usages := strings.Split(usageStr, ",")
	var keyUsage x509.KeyUsage

	usageMap := map[string]x509.KeyUsage{
		"DigitalSignature":  x509.KeyUsageDigitalSignature,
		"digital-signature": x509.KeyUsageDigitalSignature,
		"ContentCommitment": x509.KeyUsageContentCommitment,
		"KeyEncipherment":   x509.KeyUsageKeyEncipherment,
		"key-encipherment":  x509.KeyUsageKeyEncipherment,
		"DataEncipherment":  x509.KeyUsageDataEncipherment,
		"KeyAgreement":      x509.KeyUsageKeyAgreement,
		"CertSign":          x509.KeyUsageCertSign,
		"CRLSign":           x509.KeyUsageCRLSign,
	}

	for _, u := range usages {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if val, ok := usageMap[u]; ok {
			keyUsage |= val
		} else {
			return 0, fmt.Errorf("invalid key usage: %s", u)
		}
	}

	return keyUsage, nil
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
