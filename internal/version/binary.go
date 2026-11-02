package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

var digestOnce sync.Once
var digest string

func BinarySHA256() string {
	digestOnce.Do(func() {
		path, e := os.Executable()
		if e != nil {
			return
		}
		f, e := os.Open(path)
		if e != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, e = io.Copy(h, f); e == nil {
			digest = hex.EncodeToString(h.Sum(nil))
		}
	})
	return digest
}
