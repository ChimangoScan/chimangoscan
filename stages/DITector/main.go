package main

import (
	"log"

	"github.com/anonymous/DITector/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		log.Fatalln("execute cobra cmd failed with:", err)
	}
}
