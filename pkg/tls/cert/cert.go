package cert

import "github.com/spf13/cobra"

var CertCommand = cobra.Command{
	Use:   "cert",
	Short: "Manage certificates",
	Long:  "Generate, inspect, and manage certificates using Tranzia.",
}

func init() {
	CertCommand.AddCommand(&CertGenerate)
}
