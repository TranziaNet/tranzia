package cert

import "github.com/spf13/cobra"

var CertCommand = &cobra.Command{
	Use:   "cert",
	Short: "Manage certificates",
	Long:  "Generate, inspect, and manage certificates using Tranzia.",
	Example: `
# Generate a simple RSA certificate
tranzia tls cert generate --subject "/CN=example.com"
`,
}

func init() {
	CertCommand.AddCommand(CertGenerate)
	CertCommand.AddCommand(CertInspect)
}
