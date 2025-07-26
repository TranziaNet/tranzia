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
	Bits    int
	Subj    string
	Subject *Sub
	KeyType string
	//caCertFilePath     string
	//caKeyFilePath      string
	OutCertFilePath    string
	OutPrivKeyFilePath string
	OutPubKeyFilePath  string
	Validity           int
	//sanEmail           string
	Usage string
	IsCA  bool
	//pathLength         int
}
type Sub struct {
	C  []string
	O  []string
	OU []string
	L  []string
	CN string
	ST []string
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

var CertGenOpts CertGenerateOptions

var CertGenerate = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new TLS certificate",
	Long:  "Generate a new TLS certificate using customizable options like key type, SANs, validity, and CA signing through Tranzia.",
	Example: `
# Generate a 4096-bit RSA certificate valid for 1 year
tranzia tls cert generate --key-type rsa --bits 4096 --subject "/CN=example.com/L=San Francisco/O=TranziaNet/C=US"

# Generate ECDSA certificate with subject
tranzia tls cert generate --key-type ecdsa --bits 384 --subject "/CN=internal.service/O=TranziaNet/C=US"

# Generate ed25519 certificate
tranzia tls cert generate --key-type ed25519 --subject "/CN=localhost/O=TranziaNet/C=US"
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {

		err := generateRequestTemplate(cmd, args)

		return err
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		err := handleCertGeneration(&CertGenOpts)
		return err
	},
}

func generateRequestTemplate(cmd *cobra.Command, _ []string) error {
	bits, err := cmd.Flags().GetInt("bits")
	if err != nil {
		return err
	}

	CertGenOpts.Bits = bits

	subject, err := cmd.Flags().GetString("subj")
	if err != nil {
		return err
	}
	s := &Sub{}

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
				s.C = append(s.C, val)
			case "O":
				s.O = append(s.O, val)
			case "OU":
				s.OU = append(s.OU, val)
			case "L":
				s.L = append(s.L, val)
			case "ST":
				s.ST = append(s.ST, val)
			case "CN":
				s.CN = val
			}
		}

	}

	CertGenOpts.Subject = s

	keyType, err := cmd.Flags().GetString("key-type")
	if err != nil {
		return err
	}

	CertGenOpts.KeyType = keyType

	outCertFilePath, err := cmd.Flags().GetString("cert-out")
	if err != nil {
		return err
	}

	CertGenOpts.OutCertFilePath = outCertFilePath

	outPrivKeyFilePath, err := cmd.Flags().GetString("private-key-out")
	if err != nil {
		return err
	}

	CertGenOpts.OutPrivKeyFilePath = outPrivKeyFilePath

	outPubKeyFilePath, err := cmd.Flags().GetString("public-key-out")
	if err != nil {
		return err
	}

	CertGenOpts.OutPubKeyFilePath = outPubKeyFilePath

	// caCertFilePath, err := cmd.Flags().GetString("ca-cert")
	// if err != nil {
	// 	return err
	// }

	// certGenerateOptions.caCertFilePath = caCertFilePath

	// caKeyFilePath, err := cmd.Flags().GetString("ca-key")
	// if err != nil {
	// 	return err
	// }

	// certGenerateOptions.caKeyFilePath = caKeyFilePath

	validity, err := cmd.Flags().GetInt("validity")
	if err != nil {
		return err
	}

	CertGenOpts.Validity = validity

	// sanEmail, err := cmd.Flags().GetString("san-email")
	// if err != nil {
	// 	return err
	// }

	// certGenerateOptions.sanEmail = sanEmail

	usage, err := cmd.Flags().GetString("usage")
	if err != nil {
		return err
	}

	CertGenOpts.Usage = usage

	isCA, err := cmd.Flags().GetBool("is-ca")
	if err != nil {
		return err
	}

	CertGenOpts.IsCA = isCA

	// pathLength, err := cmd.Flags().GetInt("path-length")
	// if err != nil {
	// 	return err
	// }

	// certGenerateOptions.pathLength = pathLength

	return nil
}

func init() {
	CertGenerate.Flags().IntVarP(&CertGenOpts.Bits, "bits", "b", 2048, "Key size in bits (RSA: 2048/3072/4096, ECDSA: 256/384/521). Ignored for ed25519.")
	CertGenerate.Flags().StringVar(&CertGenOpts.Subj, "subj", "", "Subject in X.509 DN format, e.g., '/CN=example.com/L=City/O=Org/C=US'")
	CertGenerate.Flags().StringVar(&CertGenOpts.KeyType, "key-type", "rsa", "Type of private key to generate [rsa | ecdsa | ed25519]")

	CertGenerate.Flags().StringVar(&CertGenOpts.OutCertFilePath, "cert-out", "", "Path to save the generated certificate file")
	CertGenerate.Flags().StringVar(&CertGenOpts.OutPrivKeyFilePath, "private-key-out", "", "Path to save the generated private key file")
	CertGenerate.Flags().StringVar(&CertGenOpts.OutPubKeyFilePath, "public-key-out", "", "Path to save the generated public key file")

	// CertGenerate.Flags().StringVar(&caCertFilePath, "ca-cert", "", "Path to the root or intermediate CA certificate")
	// CertGenerate.Flags().StringVar(&caKeyFilePath, "ca-key", "", "Path to the root or intermediate CA private key")

	CertGenerate.Flags().IntVar(&CertGenOpts.Validity, "validity", 365, "Validity period of the certificate in days")
	// CertGenerate.Flags().StringVar(&sanEmail, "san-email", "", "Subject Alternative Name (SAN) email address")
	CertGenerate.Flags().StringVar(&CertGenOpts.Usage, "usage", "", "Certificate usage (e.g., server auth, client auth)")
	CertGenerate.Flags().BoolVar(&CertGenOpts.IsCA, "is-ca", false, "Mark certificate as a CA (Certificate Authority)")
	// CertGenerate.Flags().IntVar(&pathLength, "path-length", -1, "Path length constraint for CA certificates")

}

func handleCertGeneration(opts *CertGenerateOptions) error {

	privateKey, err := GenerateKeyPair(opts)
	if err != nil {
		return err
	}

	template, err := GenerateCertificateTemplate(opts)
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

	GenerateOutput(privateKey, certDER, opts)

	return err
}

func GenerateKeyPair(opts *CertGenerateOptions) (privKey any, e error) {

	var privateKey any
	var err error

	switch strings.ToLower(opts.KeyType) {
	case string(RSA):
		privateKey, err = rsa.GenerateKey(rand.Reader, opts.Bits)
		if err != nil {
			return nil, err
		}

	case string(ECDSA):
		var curve elliptic.Curve
		switch CertGenOpts.Bits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}

	case string(ED25519):
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported key type %s", opts.KeyType)
	}

	return privateKey, nil
}

func GenerateCertificateTemplate(opts *CertGenerateOptions) (*x509.Certificate, error) {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	usage, err := ParseKeyUsageStrict(opts.Usage)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         opts.Subject.CN,
			Country:            opts.Subject.C,
			Organization:       opts.Subject.O,
			OrganizationalUnit: opts.Subject.OU,
			Locality:           opts.Subject.L,
			Province:           opts.Subject.ST,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(opts.Validity) * 24 * time.Hour),
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
		// MaxPathLen:            opts.pathLength,
	}

	return &template, nil

}

func GenerateOutput(privateKey any, cert []byte, opts *CertGenerateOptions) error {

	// print generated cert to stdout
	err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	// print private key to stdout
	var pemEncodedPrivateKey []byte
	var pemEncodedPublicKey []byte

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		pemEncodedPrivateKey, err = EncodeToPem(privateKey, "RSA PRIVATE KEY")
		if err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return err
		}
		pemEncodedPublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubBytes,
		})

	case *ecdsa.PrivateKey:
		pemEncodedPrivateKey, err = EncodeToPem(privateKey, "EC PRIVATE KEY")
		if err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return err
		}
		pemEncodedPublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubBytes,
		})

	case ed25519.PrivateKey:
		pemEncodedPrivateKey, err = EncodeToPem(privateKey, "PRIVATE KEY")
		if err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			return err
		}
		pemEncodedPublicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})
	default:
		fmt.Printf("Unknown private key type: %T\n", privateKey)
	}

	fmt.Printf("%s", pemEncodedPrivateKey)

	// write data to files
	if opts.OutCertFilePath != "" {
		file, err := os.Create(opts.OutCertFilePath)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		err = pem.Encode(file, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})

	}

	if opts.OutPrivKeyFilePath != "" {
		err := os.WriteFile(opts.OutPrivKeyFilePath, pemEncodedPrivateKey, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to write private key file: %w", err))
		}
	}

	if opts.OutPubKeyFilePath != "" {
		err := os.WriteFile(opts.OutPubKeyFilePath, pemEncodedPublicKey, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to write public key file: %w", err))
		}
	}

	return nil
}
