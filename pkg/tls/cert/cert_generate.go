package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type CertGenerateOptions struct {
	bits            int
	subject         *sub
	keyType         string
	dns             string
	ip              string
	caCertFilePath  string
	caKeyFilePath   string
	outCertFilePath string
	outKeyFilePath  string
	validity        int
	sanEmail        string
	usage           string
	isCA            bool
	pathLength      int
}
type sub struct {
	c  []string
	o  []string
	ou []string
	l  []string
	cn string
	st []string
}

var (
	bits            int
	subject         string
	keyType         string
	dns             string
	ip              string
	caCertFilePath  string
	caKeyFilePath   string
	outCertFilePath string
	outKeyFilePath  string
	validity        int
	sanEmail        string
	usage           string
	isCA            bool
	pathLength      int
)

var certGenerateOptions CertGenerateOptions

var CertGenerate = cobra.Command{
	Use:   "generate",
	Short: "Generate a new TLS certificate",
	PreRunE: func(cmd *cobra.Command, args []string) error {

		err := generateRequestTemplate(cmd, args)

		return err
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		err := handleCertGeneration(&certGenerateOptions)
		return err
	},
}

func generateRequestTemplate(cmd *cobra.Command, _ []string) error {
	bits, err := cmd.Flags().GetInt("bits")
	if err != nil {
		return err
	}

	certGenerateOptions.bits = bits

	subject, err := cmd.Flags().GetString("subject")
	if err != nil {
		return err
	}
	s := &sub{}

	if strings.TrimSpace(subject) != "" {
		re := regexp.MustCompile(`/([A-Z]{1,2})=([^/]+)`)
		matches := re.FindAllStringSubmatch(subject, -1)

		// If subject is non-empty but invalid format, throw error
		if len(matches) == 0 {
			return fmt.Errorf("Invalid subject line: %q. Please follow format /C=XX/ST=.../CN=...", subject)
		}

		for _, match := range matches {
			key := strings.ToUpper(match[1])
			val := match[2]

			switch key {
			case "C":
				s.c = append(s.c, val)
			case "O":
				s.o = append(s.o, val)
			case "OU":
				s.ou = append(s.ou, val)
			case "L":
				s.l = append(s.l, val)
			case "ST":
				s.st = append(s.st, val)
			case "CN":
				s.cn = val
			}
		}

	}

	certGenerateOptions.subject = s

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		return err
	}

	certGenerateOptions.keyType = keyType

	dns, err := cmd.Flags().GetString("dns")
	if err != nil {
		return err
	}

	certGenerateOptions.dns = dns

	ip, err := cmd.Flags().GetString("ip")
	if err != nil {
		return err
	}

	certGenerateOptions.ip = ip

	outCertFilePath, err := cmd.Flags().GetString("cert-out")
	if err != nil {
		return err
	}

	certGenerateOptions.outCertFilePath = outCertFilePath

	outKeyFilePath, err := cmd.Flags().GetString("key-out")
	if err != nil {
		return err
	}

	certGenerateOptions.outKeyFilePath = outKeyFilePath

	caCertFilePath, err := cmd.Flags().GetString("ca-cert")
	if err != nil {
		return err
	}

	certGenerateOptions.caCertFilePath = caCertFilePath

	caKeyFilePath, err := cmd.Flags().GetString("ca-key")
	if err != nil {
		return err
	}

	certGenerateOptions.caKeyFilePath = caKeyFilePath

	validity, err := cmd.Flags().GetInt("validity")
	if err != nil {
		return err
	}

	certGenerateOptions.validity = validity

	sanEmail, err := cmd.Flags().GetString("san-email")
	if err != nil {
		return err
	}

	certGenerateOptions.sanEmail = sanEmail

	usage, err := cmd.Flags().GetString("usage")
	if err != nil {
		return err
	}

	certGenerateOptions.usage = usage

	isCA, err := cmd.Flags().GetBool("is-ca")
	if err != nil {
		return err
	}

	certGenerateOptions.isCA = isCA

	pathLength, err := cmd.Flags().GetInt("path-length")
	if err != nil {
		return err
	}

	certGenerateOptions.pathLength = pathLength

	return nil
}

type KeyType string

const (
	RSA     KeyType = "rsa"
	ECDSA   KeyType = "ecdsa"
	ED25519 KeyType = "ed25519"
)

func (kt *KeyType) String() string {
	return string(*kt)
}

func (kt *KeyType) Set(val string) error {
	switch val {
	case "rsa", "ecdsa", "ed25519":
		*kt = KeyType(val)
		return nil
	}
	return fmt.Errorf("key type not supported: %s", val)
}

func init() {
	CertGenerate.Flags().IntVarP(&bits, "bits", "b", 2048, "Key size in bits")
	CertGenerate.Flags().StringVar(&subject, "subject", "", "Subject for the certificate")
	CertGenerate.Flags().StringVar(&keyType, "key-type", "rsa", "[rsa|ecdsa|ed25519]")
	CertGenerate.Flags().StringVar(&dns, "dns", "", "provide DNS for SAN")
	CertGenerate.Flags().StringVar(&ip, "ip", "", "provide ip address for SAN fields")
	CertGenerate.Flags().StringVar(&outCertFilePath, "cert-out", "", "provide path to store generated cert file")
	CertGenerate.Flags().StringVar(&outCertFilePath, "key-out", "", "provide path to store generated key file")
	CertGenerate.Flags().StringVar(&caCertFilePath, "ca-cert", "", "provide path of root/intermediate certificate")
	CertGenerate.Flags().StringVar(&caCertFilePath, "ca-key", "", "provide path of root/intermediate key")
	CertGenerate.Flags().IntVar(&validity, "validity", 365, "Validity period of the certificate (e.g., 365d, 1y)")
	CertGenerate.Flags().StringVar(&sanEmail, "san-email", "", "SAN email address")
	CertGenerate.Flags().StringVar(&usage, "usage", "", "Certificate usage (e.g., server auth, client auth)")
	CertGenerate.Flags().BoolVar(&isCA, "is-ca", false, "is this a CA certificate?")
	CertGenerate.Flags().IntVar(&pathLength, "path-length", -1, "Path length for CA certificate")

}

func handleCertGeneration(opts *CertGenerateOptions) error {

	privateKey, err := generateKeyPair(opts)
	if err != nil {
		return err
	}

	template, err := generateCertificateTemplate(opts)
	if err != nil {
		return err
	}

	var certDER []byte
	// generate self-signed
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		pub := &priv.PublicKey
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	case *ecdsa.PrivateKey:
		pub := &priv.PublicKey
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	case ed25519.PrivateKey:
		pub := priv.Public().(ed25519.PublicKey)
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// generate cert-chain

	// print cert
	fmt.Println(pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	return nil
}

func generateKeyPair(opts *CertGenerateOptions) (privKey any, e error) {

	var privateKey any
	var err error

	switch strings.ToLower(opts.keyType) {
	case string(RSA):
		privateKey, err = rsa.GenerateKey(rand.Reader, opts.bits)
		if err != nil {
			return nil, err
		}

	case string(ECDSA):
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

	case string(ED25519):
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported key type %s", opts.keyType)
	}

	return privateKey, nil
}

func encodeToPem(key any, keyType string) ([]byte, error) {

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

func generateCertificateTemplate(opts *CertGenerateOptions) (*x509.Certificate, error) {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	usage, err := parseKeyUsageStrict(opts.usage)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         opts.subject.cn,
			Country:            opts.subject.c,
			Organization:       opts.subject.o,
			OrganizationalUnit: opts.subject.ou,
			Locality:           opts.subject.l,
			Province:           opts.subject.st,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(opts.validity) * 24 * time.Hour),
		KeyUsage:  usage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
		MaxPathLen:            opts.pathLength,
	}

	return &template, nil

}

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

func parseKeyUsageStrict(input string) (x509.KeyUsage, error) {
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
