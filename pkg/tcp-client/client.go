package tcpclient

import (
	"bufio"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

func init() {
	Send_command.Flags().StringP("address", "a", "127.0.0.1", "address to send tcp request")
	Send_command.Flags().StringP("port", "p", "9000", "port value")
	Send_command.Flags().StringP("message", "m", "", "message body to send to the server")
}

var Send_command = cobra.Command{
	Use: "send",
	Run: func(cmd *cobra.Command, args []string) {

		address, err := cmd.Flags().GetString("address")
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		message, err := cmd.Flags().GetString("message")
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		conn, err := net.Dial("tcp", address+":"+port)
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		defer conn.Close()

		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)

		_, err = w.WriteString(message + "\n")
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		err = w.Flush()
		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		response, err := r.ReadString('\n')

		if err != nil {
			fmt.Printf("[Error] %v\n", err)
		}

		fmt.Println("Received from server:", string(response))
	},
}
