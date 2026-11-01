package main

// Regenerate the committed Windows resources from the shared web logo.
//go:generate go run github.com/tc-hib/go-winres@v0.3.3 make --in winres.json --arch amd64,arm64 --out rsrc
