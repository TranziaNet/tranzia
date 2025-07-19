package tls

import (
	"github.com/TranziaNet/tranzia/pkg/tls/cert"
	"github.com/spf13/cobra"
)

func init() {
	TlsCommand.AddCommand(&cert.CertCommand)
}

var TlsCommand = cobra.Command{
	Use: "tls",
}
