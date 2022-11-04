package main

import (
	"encoding/json"
	"flag"
	"os"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		os.Exit(1)
	}
	if flag.Arg(0) == "get-plugin-metadata" {
		// This does not import notation-go/plugin to simplify testing setup.
		m := struct {
			Name                      string   `json:"name"`
			Description               string   `json:"description"`
			Version                   string   `json:"version"`
			URL                       string   `json:"url"`
			SupportedContractVersions []string `json:"supportedContractVersions"`
			Capabilities              []string `json:"capabilities"`
		}{Name: "foo", Description: "friendly", Version: "1", URL: "example.com", SupportedContractVersions: []string{"1"}, Capabilities: []string{"cap"}}
		data, err := json.Marshal(&m)
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(data)
	}
}
