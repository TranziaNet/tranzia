package echoserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	Echo_server_cmd.Flags().StringP("address", "a", "0.0.0.0", "address to bind")
	Echo_server_cmd.Flags().StringP("port", "p", "9000", "port to bind")
}

var Echo_server_cmd = cobra.Command{
	Use: "echo-server",
	Run: func(cmd *cobra.Command, args []string) {
		address, err := cmd.Flags().GetString("address")
		if err != nil {
			fmt.Println("[Error] could not read address from input flag")
			os.Exit(1)
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			fmt.Println("[Error] could not read port from input flag")
			os.Exit(1)
		}

		listener, err := net.Listen("tcp", address+":"+port)
		if err != nil {
			fmt.Println("[Error] could not listen on given address and port")
			os.Exit(1)
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("[Error] error while accepting connection")
				continue
			}
			go handleConnection(conn)
		}
	},
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		r := bufio.NewReader(conn)
		message, err := r.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("[Error] client disconnected")
			} else {
				fmt.Printf("[Error] %v\n", err)
			}
			return
		}

		_, err = conn.Write(message)
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
			return
		}
	}
}
