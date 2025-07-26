package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

type InspectOptions struct {
	Format     string
	OutputJSON bool
}

var InspectOpts InspectOptions

func init() {

	CertInspect.Flags().StringVar(&InspectOpts.Format, "format", "", "Specify certificate format: pem or der")
	CertInspect.Flags().BoolVar(&InspectOpts.OutputJSON, "json", false, "Output as JSON")
}

var CertInspect = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect and print details of a certificate file.",
	Long: `The 'cert inspect' command reads an X.509 certificate (PEM or DER format) and prints detailed information including:
- Subject and Issuer
- Validity period
- Serial number
- Public key algorithm and key size
- Extensions (e.g., SANs, Key Usage, Extended Key Usage)
- Whether it is a CA certificate

This is useful for debugging, verifying certificate contents, and understanding certificate chains. You can use this command for both leaf and intermediate/CA certificates.

Supports local file input or stdin.
`,
	Example: `
  # Inspect a certificate from file
    tranzia cert inspect ./mycert.pem

  # Inspect a DER-encoded certificate
    tranzia cert inspect ./cert.der --format der

  # Inspect a certificate piped from another command
    cat cert.pem | tranzia cert inspect

  # Inspect with JSON output
    tranzia cert inspect cert.pem --output json
`,
	RunE: func(cmd *cobra.Command, args []string) error {

		err := runCertInspect(cmd, args)
		return err
	},
}

func runCertInspect(_ *cobra.Command, args []string) error {
	var input io.Reader
	var err error

	if len(args) > 0 {
		file, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open certificate file: %w", err)
		}
		defer file.Close()
		input = file
	} else {
		input = os.Stdin
	}

	certBytes, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	var cert *x509.Certificate

	switch {
	case InspectOpts.Format == "pem" || (InspectOpts.Format == "" && strings.Contains(string(certBytes), "BEGIN CERTIFICATE")):
		block, _ := pem.Decode(certBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("failed to parse PEM certificate")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
	case InspectOpts.Format == "der" || InspectOpts.Format != "":
		cert, err = x509.ParseCertificate(certBytes)
	default:
		return errors.New("unable to determine certificate format, use --format to specify")
	}

	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if InspectOpts.OutputJSON {
		certInfo := &CertInfo{}
		info := certInfo.ExtractCertInfo(cert)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	printCertText(cert)
	return nil
}

func printCertText(cert *x509.Certificate) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	write := func(key, value string) {
		fmt.Fprintf(w, "%s:\t%s\n", key, value)
	}

	write("Subject", cert.Subject.String())
	write("Issuer", cert.Issuer.String())
	write("Serial Number", cert.SerialNumber.String())
	write("Not Before", cert.NotBefore.String())
	write("Not After", cert.NotAfter.String())

	// Public Key info
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		write("Public Key", fmt.Sprintf("RSA (%d bits)", pub.Size()*8))
	case *ecdsa.PublicKey:
		write("Public Key", fmt.Sprintf("ECDSA (%d bits)", pub.Curve.Params().BitSize))
	case ed25519.PublicKey:
		write("Public Key", fmt.Sprintf("Ed25519 (%d bits)", len(pub)*8))
	default:
		write("Public Key", "Unknown")
	}

	write("Is CA", strconv.FormatBool(cert.IsCA))

	if len(cert.DNSNames) > 0 {
		write("DNS Names", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		write("Email Addresses", strings.Join(cert.EmailAddresses, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		write("IP Addresses", joinIPs(cert.IPAddresses))
	}
	if len(cert.ExtKeyUsage) > 0 {
		write("Key Usage", joinEKUs(cert.ExtKeyUsage))
	}

	w.Flush()
}

func joinIPs(ips []net.IP) string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return strings.Join(out, ", ")
}

func joinEKUs(usages []x509.ExtKeyUsage) string {
	var out []string
	for _, u := range usages {
		out = append(out, ekuString(u))
	}
	return strings.Join(out, ", ")
}

func ekuString(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	default:
		return fmt.Sprintf("Unknown(%d)", u)
	}
}
