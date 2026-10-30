package main

import (
	"fmt"
	"os"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/winagent"
)

func main() {
	if err := winagent.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Zireael-RMM:", err)
		os.Exit(1)
	}
}
