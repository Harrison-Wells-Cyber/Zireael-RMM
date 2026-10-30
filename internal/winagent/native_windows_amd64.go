package winagent

import _ "embed"

//go:embed native/amd64.exe
var desktopEngine []byte

const engineSHA256 = "cbf10a37fc01f74f2473aeca0a4b391dca6f9d0a8d0300aa7181dbce7bacc51e"
