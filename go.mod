module github.com/notaryproject/notation-go

go 1.21

require (
	github.com/go-ldap/ldap/v3 v3.4.7
	github.com/notaryproject/notation-core-go v1.0.3-0.20240325061945-807a3386734e
	github.com/notaryproject/notation-plugin-framework-go v1.0.0
	github.com/notaryproject/tspclient-go v0.0.0-20240122083733-a373599795a2
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/veraison/go-cose v1.1.0
	golang.org/x/crypto v0.21.0
	golang.org/x/mod v0.17.0
	oras.land/oras-go/v2 v2.5.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/fxamacker/cbor/v2 v2.6.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sync v0.6.0 // indirect
)

replace github.com/notaryproject/notation-core-go => github.com/Two-Hearts/notation-core-go v0.0.0-20240418044922-14d05519328b

replace github.com/notaryproject/tspclient-go => github.com/Two-Hearts/tspclient-go v0.0.0-20240410033505-94c3b3def019
