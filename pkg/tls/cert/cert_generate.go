package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type CertGenerateOptions struct {
	bits            int
	cn              string
	keyType         string
	dns             string
	ip              string
	caCertFilePath  string
	caKeyFilePath   string
	outCertFilePath string
	outKeyFilePath  string
	validity        string
	sanEmail        string
	usage           string
	isCA            bool
	pathLength      int
}

type CertOptions struct {
	publicKey  []byte
	privateKey []byte
}

var (
	bits            int
	cn              string
	keyType         string
	dns             string
	ip              string
	caCertFilePath  string
	caKeyFilePath   string
	outCertFilePath string
	outKeyFilePath  string
	validity        string
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

	cn, err := cmd.Flags().GetString("cn")
	if err != nil {
		return err
	}

	certGenerateOptions.cn = cn

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

	validity, err := cmd.Flags().GetString("validity")
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
	CertGenerate.Flags().StringVarP(&cn, "cn", "c", "example.com", "Common Name")
	CertGenerate.Flags().StringVar(&keyType, "key-type", "rsa", "[rsa|ecdsa|ed25519]")
	CertGenerate.Flags().StringVar(&dns, "dns", "", "provide DNS for SAN")
	CertGenerate.Flags().StringVar(&ip, "ip", "", "provide ip address for SAN fields")
	CertGenerate.Flags().StringVar(&outCertFilePath, "cert-out", "", "provide path to store generated cert file")
	CertGenerate.Flags().StringVar(&outCertFilePath, "key-out", "", "provide path to store generated key file")
	CertGenerate.Flags().StringVar(&caCertFilePath, "ca-cert", "", "provide path of root/intermediate certificate")
	CertGenerate.Flags().StringVar(&caCertFilePath, "ca-key", "", "provide path of root/intermediate key")
	CertGenerate.Flags().StringVar(&validity, "validity", "365d", "Validity period of the certificate (e.g., 365d, 1y)")
	CertGenerate.Flags().StringVar(&sanEmail, "san-email", "", "SAN email address")
	CertGenerate.Flags().StringVar(&usage, "usage", "", "Certificate usage (e.g., server auth, client auth)")
	CertGenerate.Flags().BoolVar(&isCA, "is-ca", false, "is this a CA certificate?")
	CertGenerate.Flags().IntVar(&pathLength, "path-length", -1, "Path length for CA certificate")

}

func handleCertGeneration(opts *CertGenerateOptions) error {

	_, _, err := generateKeyPair(opts)
	if err != nil {
		return err
	}

	// fmt.Printf("%s", key)

	return nil
}

func generateKeyPair(opts *CertGenerateOptions) ([]byte, []byte, error) {

	var privateKey any
	var publicKey any
	var err error

	switch strings.ToLower(opts.keyType) {
	case string(RSA):
		privateKey, err = rsa.GenerateKey(rand.Reader, opts.bits)
		if err != nil {
			return nil, nil, err
		}
		publicKey = privateKey.(*rsa.PrivateKey).PublicKey

	case string(ECDSA):
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		publicKey = privateKey.(*ecdsa.PrivateKey).PublicKey

	case string(ED25519):
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

	default:
		return nil, nil, fmt.Errorf("unsupported key type %s", opts.keyType)
	}

	privateDer, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	privatePem := pem.EncodeToMemory(&pem.Block{
		Type:  fmt.Sprintf("%s PRIVATE KEY", opts.keyType),
		Bytes: privateDer,
	})

	publicDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	publicPem := pem.EncodeToMemory(&pem.Block{
		Type:  fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(opts.keyType)),
		Bytes: publicDer,
	})

	return publicPem, privatePem, nil

}

// func generateCertificate(opts *CertGenerateOptions) {

// }
