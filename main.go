package main

import (
	"os"

	"github.com/valli0x/signature-escrow/cmd"
)

func main() {
	if err := cmd.Start(); err != nil {
		// Cobra will print the error
		os.Exit(1)
	}
}
