package cmd

import (
	"github.com/TranziaNet/tranzia/pkg"
	echoserver "github.com/TranziaNet/tranzia/pkg/echo-server"
	tcpclient "github.com/TranziaNet/tranzia/pkg/tcp-client"
	"github.com/TranziaNet/tranzia/pkg/tls"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:     "tranzia",
	Short:   "Tranzia CLI: All-in-one network testing toolkit",
	Long:    "Tranzia unifies networking tools like nc, curl, openssl, tcpdump into one modern CLI.",
	Version: pkg.Version,
}

func init() {
	RootCmd.AddCommand(&echoserver.Echo_server_cmd)
	RootCmd.AddCommand(&tcpclient.Send_command)
	RootCmd.AddCommand(tls.TlsCommand)
}
