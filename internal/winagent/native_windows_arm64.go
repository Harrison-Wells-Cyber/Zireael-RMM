package winagent

import _ "embed"

//go:embed native/arm64.exe
var desktopEngine []byte

const engineSHA256 = "313014760c76e5233315c8610c90f45ff43052572fbf076a352508a8aa54e2b5"
