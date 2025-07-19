package main

import (
	"fmt"
	"os"

	"github.com/TranziaNet/tranzia/pkg"
	echoserver "github.com/TranziaNet/tranzia/pkg/echo-server"
	tcpclient "github.com/TranziaNet/tranzia/pkg/tcp-client"
	tls "github.com/TranziaNet/tranzia/pkg/tls"
	"github.com/spf13/cobra"
)

var rootCmd = cobra.Command{
	Use:     "tranzia",
	Version: pkg.Version,
}

func init() {
	rootCmd.AddCommand(&echoserver.Echo_server_cmd)
	rootCmd.AddCommand(&tcpclient.Send_command)
	rootCmd.AddCommand(&tls.TlsCommand)
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
