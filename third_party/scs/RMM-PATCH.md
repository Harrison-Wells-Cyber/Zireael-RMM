# Local patch to SCS v2.9.0

Upstream: https://github.com/alexedwards/scs/tree/v2.9.0

Copied from the checksum-verified Go module `github.com/alexedwards/scs/v2@v2.9.0`. Its MIT license remains in LICENSE. This directory is not relicensed under the root CC0 declaration.

Change: `memstore/memstore.go` initializes the janitor stop channel in the constructor before starting its goroutine, and uses `sync.Once` to close it during shutdown. Upstream initializes the channel inside the goroutine; immediate application shutdown races with that write and may fail to stop the janitor. Our actual passkey tests exposed this with `go test -race`.

No session token generation, codec, or WebAuthn verification is modified. `memstore/rmm_shutdown_test.go` exercises immediate and repeated shutdown. Remove this local replacement when a verified upstream release includes an equivalent fix.

The upstream `TestCleanupInterval` directly reads/writes the internal map while its janitor runs. Its fixture now takes the existing map mutex so the upstream test itself passes the race detector; assertions and runtime behavior are unchanged.

## Failed session commits

`session.go` now stops forwarding the handler's status/body when committing a session fails. Upstream calls `ErrorFunc` but then continues writing the original handler response, which can concatenate a successful JSON body onto the error. Our store deliberately rejects late commits to sessions retired by concurrent logout or token rotation. Those rejections now produce one HTTP 401 response with no replacement cookie; unexpected store failures remain HTTP 500.

`rmm_commit_failure_test.go` covers implicit/explicit response headers and repeated writes after rejection. The application's `TestRetiredSessionCannotAppendSuccessfulResponse` holds a real authenticated request across logout and verifies valid error JSON, no private payload, no stale file-response headers and no revived session. The complete vendored module is tested with the race detector. Remove this patch only after verifying equivalent upstream behavior.
