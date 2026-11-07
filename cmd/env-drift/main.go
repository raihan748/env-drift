// Package main provides the entry point for the env-drift CLI tool.
package main

import (
	"fmt"
	"os"
)

var (
	// Version is the current application version.
	Version = "0.1.0"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("env-drift version %s\n", Version)
		return
	}
	fmt.Println("env-drift: multi-environment .env schema and drift analyzer")
}
