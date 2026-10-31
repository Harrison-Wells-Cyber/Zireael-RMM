// Package zireael carries the license texts distributed with the standalone
// binaries. The original project code remains CC0.
package zireael

import _ "embed"

// ThirdPartyNotices contains the notices for the code linked into our binaries.
//
//go:embed THIRD_PARTY_NOTICES.md
var ThirdPartyNotices string
