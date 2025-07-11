package main

import (
	"fmt"
	"os"

	"github.com/TranziaNet/tranzia/pkg"
	echoserver "github.com/TranziaNet/tranzia/pkg/echo-server"
	tcpclient "github.com/TranziaNet/tranzia/pkg/tcp-client"
	"github.com/spf13/cobra"
)

var rootCmd = cobra.Command{
	Use: "tranzia",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: implement necessary function
		fmt.Println("Hello world!")
	},
	Version: pkg.Version,
}

func init() {
	rootCmd.AddCommand(&echoserver.Echo_server_cmd)
	rootCmd.AddCommand(&tcpclient.Send_command)
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
