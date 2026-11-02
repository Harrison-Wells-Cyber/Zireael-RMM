//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	raw, e := os.ReadFile("../../internal/version/VERSION")
	if e != nil {
		panic(e)
	}
	v := strings.TrimSpace(string(raw))
	fixed, _, _ := strings.Cut(v, "-")
	fixed, _, _ = strings.Cut(fixed, "+")
	fixed += ".0"
	raw, e = os.ReadFile("winres.json")
	if e != nil {
		panic(e)
	}
	var data map[string]any
	if e = json.Unmarshal(raw, &data); e != nil {
		panic(e)
	}
	data["RT_RCDATA"] = map[string]any{"#100": map[string]string{"0000": "../../internal/version/VERSION"}}
	versions := data["RT_VERSION"].(map[string]any)["#1"].(map[string]any)["0000"].(map[string]any)
	f := versions["fixed"].(map[string]any)
	f["file_version"], f["product_version"] = fixed, fixed
	info := versions["info"].(map[string]any)["0409"].(map[string]any)
	info["ProductVersion"], info["FileVersion"] = v, v
	raw, e = json.MarshalIndent(data, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile("winres.json", append(raw, '\n'), 0644); e != nil {
		panic(e)
	}
	cmd := exec.Command("go", "run", "github.com/tc-hib/go-winres@v0.3.3", "make", "--in", "winres.json", "--arch", "amd64,arm64", "--out", "rsrc")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if e = cmd.Run(); e != nil {
		panic(e)
	}
	fmt.Println("Windows resources:", v)
}
