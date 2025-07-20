package main

import (
	"fmt"
	"os"

	cmd "github.com/TranziaNet/tranzia/pkg/cmd"
)

func main() {

	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
