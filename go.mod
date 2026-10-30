module github.com/Harrison-Wells-Cyber/Zireael-RMM

go 1.27.3

require (
	github.com/Microsoft/go-winio v0.6.4
	github.com/alexedwards/scs/v2 v2.9.0
	github.com/coder/websocket v1.8.15
	github.com/fxamacker/cbor/v2 v2.9.4
	github.com/go-webauthn/webauthn v0.18.2
	go.etcd.io/bbolt v1.5.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.49.0
	golang.org/x/time v0.16.0
)

require (
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/alexedwards/scs/v2 => ./third_party/scs
