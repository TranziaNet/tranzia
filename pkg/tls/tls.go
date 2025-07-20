package tls

import (
	"github.com/TranziaNet/tranzia/pkg/tls/cert"
	"github.com/spf13/cobra"
)

func init() {
	TlsCommand.AddCommand(cert.CertCommand)
}

var TlsCommand = &cobra.Command{
	Use:   "tls",
	Short: "TLS tools (certificate generation, handshake testing etc)",
	Long:  "TLS tools including certificate management and handshake testing commands under Tranzia.",
}
