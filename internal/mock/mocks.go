package mock

import (
	"context"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/manager"
	"github.com/notaryproject/notation-go/registry"
	"github.com/opencontainers/go-digest"
	"strings"
)

var (
	SampleArtifactUri   = "registry.acme-rockets.io/software/net-monitor@sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333"
	SampleDigest        = digest.FromString("sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333")
	Annotations         = map[string]string{"key": "value"}
	JwsSigEnvDescriptor = notation.Descriptor{
		MediaType:   "application/jose+json",
		Digest:      SampleDigest,
		Size:        100,
		Annotations: Annotations,
	}

	/*
			This mock repository returns a valid Signature Envelope by default. Parsed Signature Envelope is
			{
		    "Payload": {
		        "targetArtifact": {
		            "mediaType": "application/vnd.oci.image.manifest.v1+json",
		            "digest": "sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333",
		            "size": 16724,
		            "annotations": {
		                "io.wabbit-networks.buildId": "123"
		            }
		        }
		    },
		    "PayloadContentType": "application/vnd.cncf.notary.v2.jws.v1",
		    "SignedAttributes": {
		        "SigningTime": "2022-06-24T10:56:22-07:00",
		        "Expiry": "2022-06-25T10:56:22-07:00",
		        "ExtendedAttributes": [{
		            "Key": "signedCritKey1",
		            "Critical": true,
		            "Value": "signedValue1"
		        }, {
		            "Key": "signedKey1",
		            "Critical": false,
		            "Value": "signedKey2"
		        }]
		    },
		    "UnsignedAttributes": {
		        "SigningAgent": "NotationUnitTest/1.0.0"
		    },
		    "SignatureAlgorithm": "RSASSA_PSS_SHA_384",
		    "CertificateChain": [{
		        "Raw": "MIIEfDCCAuSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEbMBkGA1UEAxMSTm90YXRpb24gVGVzdCBSb290MB4XDTIyMDYyNDE3NTYyMloXDTIyMDYyNTE3NTYyMlowXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxIDAeBgNVBAMTF05vdGF0aW9uIFRlc3QgTGVhZiBDZXJ0MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAoXrZa9kJb3wbW2UthGcz382LBKDca3+vp5dv/3EOSZIvlofUWrtoIUcBOZLUfG+IBJvCZaxBrmLEYG0j/82BUB6s2abqQKKG3IN+/sfFa71zyQgsQwFjRn+9xjTqPYw+AU58JbGVy2i08/zBaGnEBMfR5ZN5AKTi9U3r5ImyldPK1BsBfH6PKs7tUwNsquIl2x4RdTTNl8husOFHLs+IFxJvNdTTG+SF5LSMLE6YUSJQGBd73vD+i5t7REQCs60TAGdZEjXHy83s+GHfNZ7QqB/4Ic9+cm0KibV8porDxZ08cuVJpyCxS9Y1UqewENC2Bv+THXUsrpEwI24+/zDX9qWDmXovVKXlWKJNyC6lfpyaHbLy16MahN5DNzgzAKEg1nNrwj310sodwjOAlBEGzzVVtarRasmJxyK8zTMEMWNU/wfivEmshwDmDP5d69ahpwv2pxxite/mCIdq2NWrtPyEgt93LdZMg3sBok3xrEPVzSMTdvz7DEYJ42jpC7bfAgMBAAGjSDBGMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAWgBSKBGCoAu++5bIcPlTOR480pJtNezANBgkqhkiG9w0BAQsFAAOCAYEAhadLSl5E6tKSztFeDQPsLoAMs1xXbnfevZcUVEhjS7U1XJjDdgCHRWUKKUo6J7zPYj9t6S0V93ClDI5mdtxZlx2SKhE973E5euVUrppV+AbAn9z6GiJiR3gMeuRc4RjbiFiPR2b4qz1t9uQWcjfq/zSPxsvwB8JqKVgHZyFhtyh0CRc0W3NxOvBBR9fKBv7GQArg9KGmG6TbUPoy+4Twl+UZhx8tkHBYAH0P+BroyKuERF8CFdrrQE2MiGi7ZORQvCLQEt93hH4SRyBQI+PWiTPg6bxoCiVJh4jReSwsvBMczu/x/Hpx6n+QocZXr2e2snHav9IC8X0+3U3FAVhAL4iasqimwoN2I1HUNESF1gQJBGOMesq7CpAMG3dfk0S3tWx3kTKib43LsP85Vxddw9PL74+q0iOvnYXEnA5j0EHe9Uu4LpPKewns7IPxBin1jZxkE3BXPGTH/g7D5BjhkAYnGCf0ynGX9wwOMipHJ1HkdVAQmwOqWXs9sqItEE7b",
		        "RawTBSCertificate": "MIIC5KADAgECAgECMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MRswGQYDVQQDExJOb3RhdGlvbiBUZXN0IFJvb3QwHhcNMjIwNjI0MTc1NjIyWhcNMjIwNjI1MTc1NjIyWjBfMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEgMB4GA1UEAxMXTm90YXRpb24gVGVzdCBMZWFmIENlcnQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQChetlr2QlvfBtbZS2EZzPfzYsEoNxrf6+nl2//cQ5Jki+Wh9Rau2ghRwE5ktR8b4gEm8JlrEGuYsRgbSP/zYFQHqzZpupAoobcg37+x8VrvXPJCCxDAWNGf73GNOo9jD4BTnwlsZXLaLTz/MFoacQEx9Hlk3kApOL1TevkibKV08rUGwF8fo8qzu1TA2yq4iXbHhF1NM2XyG6w4Ucuz4gXEm811NMb5IXktIwsTphRIlAYF3ve8P6Lm3tERAKzrRMAZ1kSNcfLzez4Yd81ntCoH/ghz35ybQqJtXymisPFnTxy5UmnILFL1jVSp7AQ0LYG/5MddSyukTAjbj7/MNf2pYOZei9UpeVYok3ILqV+nJodsvLXoxqE3kM3ODMAoSDWc2vCPfXSyh3CM4CUEQbPNVW1qtFqyYnHIrzNMwQxY1T/B+K8SayHAOYM/l3r1qGnC/anHGK17+YIh2rY1au0/ISC33ct1kyDewGiTfGsQ9XNIxN2/PsMRgnjaOkLtt8CAwEAAaNIMEYwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFIoEYKgC777lshw+VM5HjzSkm017",
		        "RawSubjectPublicKeyInfo": "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAoXrZa9kJb3wbW2UthGcz382LBKDca3+vp5dv/3EOSZIvlofUWrtoIUcBOZLUfG+IBJvCZaxBrmLEYG0j/82BUB6s2abqQKKG3IN+/sfFa71zyQgsQwFjRn+9xjTqPYw+AU58JbGVy2i08/zBaGnEBMfR5ZN5AKTi9U3r5ImyldPK1BsBfH6PKs7tUwNsquIl2x4RdTTNl8husOFHLs+IFxJvNdTTG+SF5LSMLE6YUSJQGBd73vD+i5t7REQCs60TAGdZEjXHy83s+GHfNZ7QqB/4Ic9+cm0KibV8porDxZ08cuVJpyCxS9Y1UqewENC2Bv+THXUsrpEwI24+/zDX9qWDmXovVKXlWKJNyC6lfpyaHbLy16MahN5DNzgzAKEg1nNrwj310sodwjOAlBEGzzVVtarRasmJxyK8zTMEMWNU/wfivEmshwDmDP5d69ahpwv2pxxite/mCIdq2NWrtPyEgt93LdZMg3sBok3xrEPVzSMTdvz7DEYJ42jpC7bfAgMBAAE=",
		        "RawSubject": "MF8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MSAwHgYDVQQDExdOb3RhdGlvbiBUZXN0IExlYWYgQ2VydA==",
		        "RawIssuer": "MFoxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MRswGQYDVQQDExJOb3RhdGlvbiBUZXN0IFJvb3Q=",
		        "Signature": "hadLSl5E6tKSztFeDQPsLoAMs1xXbnfevZcUVEhjS7U1XJjDdgCHRWUKKUo6J7zPYj9t6S0V93ClDI5mdtxZlx2SKhE973E5euVUrppV+AbAn9z6GiJiR3gMeuRc4RjbiFiPR2b4qz1t9uQWcjfq/zSPxsvwB8JqKVgHZyFhtyh0CRc0W3NxOvBBR9fKBv7GQArg9KGmG6TbUPoy+4Twl+UZhx8tkHBYAH0P+BroyKuERF8CFdrrQE2MiGi7ZORQvCLQEt93hH4SRyBQI+PWiTPg6bxoCiVJh4jReSwsvBMczu/x/Hpx6n+QocZXr2e2snHav9IC8X0+3U3FAVhAL4iasqimwoN2I1HUNESF1gQJBGOMesq7CpAMG3dfk0S3tWx3kTKib43LsP85Vxddw9PL74+q0iOvnYXEnA5j0EHe9Uu4LpPKewns7IPxBin1jZxkE3BXPGTH/g7D5BjhkAYnGCf0ynGX9wwOMipHJ1HkdVAQmwOqWXs9sqItEE7b",
		        "SignatureAlgorithm": 4,
		        "PublicKeyAlgorithm": 1,
		        "PublicKey": {
		            "N": 3664587810453473860512512675713532199137578718916808572150721625682450230246874301386773740339557650101984237659541687349939682542612274257520998644035430138481874497248630993450331870265994396678188146792777419620386654211356548623753443905501078470665243314333771005252145923606909108571527990247988845402120844593245153389339618180806102897481004497647626058967254392864744496295177981201799870812365651240161387031055169638982449643393404097754041866647452135301872587209412263484291698138682729186056841493939859309924194132069657286371591777838900397396603764684831618645489870303079565544517305980788180170461663698995314768676862631406317524029483450886062651897929511823637045438256850306722409593852583640602302158031786622137337440696805492217819518587118149468337219211075645916266452959015199255314518581540112870074407982702769175992636111107775338344335253759239159187551101902468905603222610437199262124848863,
		            "E": 65537
		        },
		        "Version": 3,
		        "SerialNumber": 2,
		        "Issuer": {
					...
		        },
		        "Subject": {
					...
		        },
		        "NotBefore": "2022-06-24T17:56:22Z",
		        "NotAfter": "2022-06-25T17:56:22Z",
		        "KeyUsage": 1,
		        "Extensions": [{
					...
		        }],
		        "ExtraExtensions": null,
		        "UnhandledCriticalExtensions": null,
		        "ExtKeyUsage": [3],
		        "UnknownExtKeyUsage": null,
		        "BasicConstraintsValid": false,
		        "IsCA": false,
		        "MaxPathLen": 0,
		        "MaxPathLenZero": false,
		        "SubjectKeyId": null,
		        "AuthorityKeyId": "igRgqALvvuWyHD5UzkePNKSbTXs=",
		        "OCSPServer": null,
		        "IssuingCertificateURL": null,
		        "DNSNames": null,
		        "EmailAddresses": null,
		        "IPAddresses": null,
		        "URIs": null,
		        "PermittedDNSDomainsCritical": false,
		        "PermittedDNSDomains": null,
		        "ExcludedDNSDomains": null,
		        "PermittedIPRanges": null,
		        "ExcludedIPRanges": null,
		        "PermittedEmailAddresses": null,
		        "ExcludedEmailAddresses": null,
		        "PermittedURIDomains": null,
		        "ExcludedURIDomains": null,
		        "CRLDistributionPoints": null,
		        "PolicyIdentifiers": null
		    }, {
		        "Raw": "MIIEiTCCAvGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEbMBkGA1UEAxMSTm90YXRpb24gVGVzdCBSb290MB4XDTIyMDYyNDE3NTYyMVoXDTIyMDcyNDE3NTYyMVowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxGzAZBgNVBAMTEk5vdGF0aW9uIFRlc3QgUm9vdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAK+1W8JztxWYge6R8QFJCOJuJ0al9etIdakrDSm87Cf14L1zCbkOPWOA0+L+1QLXwviYJ5NpcdTtNLczLJtgigCdZMxfK3ZODu47sT+9EJut85hguyUSvcHiwhKr8Qa7kLi7sE4svgje/L3paPuQr14TgMb1Tun3XAy5OnvGjMGKi1/zkJ6BCgXya/8L/oyaKgChEPDjY/xjWKTF+2Pzeq9ZLiHqNBjRHBqVUvYNtlPtb5SJm66r/IUtdNd8BA4gLEwIqVEruCN1895heybqcYR7vxomJ4/otLeb35En36+6MdOquDg/tuBciS1sXO/j6ZHpGDYGx3uqTIz7aNkRYvbejR/fq4mpaxLbRkNazg1PFIFmekOKJxQWRY7ap8c9XS6ABpOHQISh5vsev93LeEltnzOYUHNvKWJuz2YwA/hsPP8LaQVZRDL3iNtaTeL7rjSvNSLNyjI9LKyoNEAQ/PZBBhFIv/actIyY1pXyHvNzt11Mmf9JJ2BQz00mAaUfxwIDAQABo1owWDAOBgNVHQ8BAf8EBAMCAgQwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUigRgqALvvuWyHD5UzkePNKSbTXswDQYJKoZIhvcNAQELBQADggGBAGLiCmT97QfoYYuPJUZZXsLxFlJ71FmxRzUZ5c8dfAbFio/dEa54Ywzj8h+D9UYxsIcsAEHPZJHVsNJieYfHoOnGgVLBQrRcfayy+MhZQRAm7lB0U/e1H9XNtolX9USa/9N7MiLYlHhJU9dK6IFM8KItiC9IJ0aK4dRjFFb7RHMRoMeGXjZbFY0XfdvNlpT+PtrCU51BLEwD2MZfcSszxJpBK1+3nbVkIJ3jH55uwgsDDJMx9+fHCSaXPYCJo1/RAwWNrkrx88XSGFnr9PakJkzJaJKQinR603xQct27TBnIqnLq4dzibvJmRAf+PI/h0tplzE+vDJzPjz75hYj3QobC2tS81My6Ql0Urs3GZjIIX3ToBmsLyxz4QKDifdi9uenoadZiUwiX1ooFhtXHFOFIE5ZvrOPfEEsAiU4Hkvmukol688f7LfLHj2fABUurNcxTCSiI3pSKtl0vj3Px0a2R0ubVO+LJTpf7uHw1XFesYnCiPrS2r4y94I5S1ldxaA==",
		        "RawTBSCertificate": "MIIC8aADAgECAgEBMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MRswGQYDVQQDExJOb3RhdGlvbiBUZXN0IFJvb3QwHhcNMjIwNjI0MTc1NjIxWhcNMjIwNzI0MTc1NjIxWjBaMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEbMBkGA1UEAxMSTm90YXRpb24gVGVzdCBSb290MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr7VbwnO3FZiB7pHxAUkI4m4nRqX160h1qSsNKbzsJ/XgvXMJuQ49Y4DT4v7VAtfC+Jgnk2lx1O00tzMsm2CKAJ1kzF8rdk4O7juxP70Qm63zmGC7JRK9weLCEqvxBruQuLuwTiy+CN78velo+5CvXhOAxvVO6fdcDLk6e8aMwYqLX/OQnoEKBfJr/wv+jJoqAKEQ8ONj/GNYpMX7Y/N6r1kuIeo0GNEcGpVS9g22U+1vlImbrqv8hS1013wEDiAsTAipUSu4I3Xz3mF7JupxhHu/GiYnj+i0t5vfkSffr7ox06q4OD+24FyJLWxc7+PpkekYNgbHe6pMjPto2RFi9t6NH9+rialrEttGQ1rODU8UgWZ6Q4onFBZFjtqnxz1dLoAGk4dAhKHm+x6/3ct4SW2fM5hQc28pYm7PZjAD+Gw8/wtpBVlEMveI21pN4vuuNK81Is3KMj0srKg0QBD89kEGEUi/9py0jJjWlfIe83O3XUyZ/0knYFDPTSYBpR/HAgMBAAGjWjBYMA4GA1UdDwEB/wQEAwICBDATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSKBGCoAu++5bIcPlTOR480pJtNew==",
		        "RawSubjectPublicKeyInfo": "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr7VbwnO3FZiB7pHxAUkI4m4nRqX160h1qSsNKbzsJ/XgvXMJuQ49Y4DT4v7VAtfC+Jgnk2lx1O00tzMsm2CKAJ1kzF8rdk4O7juxP70Qm63zmGC7JRK9weLCEqvxBruQuLuwTiy+CN78velo+5CvXhOAxvVO6fdcDLk6e8aMwYqLX/OQnoEKBfJr/wv+jJoqAKEQ8ONj/GNYpMX7Y/N6r1kuIeo0GNEcGpVS9g22U+1vlImbrqv8hS1013wEDiAsTAipUSu4I3Xz3mF7JupxhHu/GiYnj+i0t5vfkSffr7ox06q4OD+24FyJLWxc7+PpkekYNgbHe6pMjPto2RFi9t6NH9+rialrEttGQ1rODU8UgWZ6Q4onFBZFjtqnxz1dLoAGk4dAhKHm+x6/3ct4SW2fM5hQc28pYm7PZjAD+Gw8/wtpBVlEMveI21pN4vuuNK81Is3KMj0srKg0QBD89kEGEUi/9py0jJjWlfIe83O3XUyZ/0knYFDPTSYBpR/HAgMBAAE=",
		        "RawSubject": "MFoxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MRswGQYDVQQDExJOb3RhdGlvbiBUZXN0IFJvb3Q=",
		        "RawIssuer": "MFoxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEPMA0GA1UEChMGTm90YXJ5MRswGQYDVQQDExJOb3RhdGlvbiBUZXN0IFJvb3Q=",
		        "Signature": "YuIKZP3tB+hhi48lRllewvEWUnvUWbFHNRnlzx18BsWKj90RrnhjDOPyH4P1RjGwhywAQc9kkdWw0mJ5h8eg6caBUsFCtFx9rLL4yFlBECbuUHRT97Uf1c22iVf1RJr/03syItiUeElT10rogUzwoi2IL0gnRorh1GMUVvtEcxGgx4ZeNlsVjRd9282WlP4+2sJTnUEsTAPYxl9xKzPEmkErX7edtWQgneMfnm7CCwMMkzH358cJJpc9gImjX9EDBY2uSvHzxdIYWev09qQmTMlokpCKdHrTfFBy3btMGciqcurh3OJu8mZEB/48j+HS2mXMT68MnM+PPvmFiPdChsLa1LzUzLpCXRSuzcZmMghfdOgGawvLHPhAoOJ92L256ehp1mJTCJfWigWG1ccU4UgTlm+s498QSwCJTgeS+a6SiXrzx/st8sePZ8AFS6s1zFMJKIjelIq2XS+Pc/HRrZHS5tU74slOl/u4fDVcV6xicKI+tLavjL3gjlLWV3Fo",
		        "SignatureAlgorithm": 4,
		        "PublicKeyAlgorithm": 1,
		        "PublicKey": {
		            "N": 3987487329846377749992412297553044313345448948194728650822485947959031944617710977893953339049189551436543448896480557849507820382774268109199256976131646987447294876857282451948695251552754431862290709830663353678193467672804825445883582598667748871121971682991539192053121850578881973704657015912259599555874513011996423753757621967896979022886726285518067155993673058101831700974318124566457858784748883148986743729677575652733887448697188562222932384961028845149162535419503333453516738309786784393232548602441644084130838826176378983700058588533638153782443041563863412819498130378656237507483073220251299336930318299266247807983397169983811821868071489628177684983258300219337725023316429538559708593764816106214416951868945153045024491424655647168757522807288609792188796510303508603531541349034583884394442314512898221711773195140875707374602665376345437968937596053968828046074713856318676425920296840281987465158599,
		            "E": 65537
		        },
		        "Version": 3,
		        "SerialNumber": 1,
		        "Issuer": {
					...
		        },
		        "Subject": {
					...
		        },
		        "NotBefore": "2022-06-24T17:56:21Z",
		        "NotAfter": "2022-07-24T17:56:21Z",
		        "KeyUsage": 32,
		        "Extensions": [{
					...
		        }],
		        "ExtraExtensions": null,
		        "UnhandledCriticalExtensions": null,
		        "ExtKeyUsage": [3],
		        "UnknownExtKeyUsage": null,
		        "BasicConstraintsValid": true,
		        "IsCA": true,
		        "MaxPathLen": 1,
		        "MaxPathLenZero": false,
		        "SubjectKeyId": "igRgqALvvuWyHD5UzkePNKSbTXs=",
		        "AuthorityKeyId": null,
		        "OCSPServer": null,
		        "IssuingCertificateURL": null,
		        "DNSNames": null,
		        "EmailAddresses": null,
		        "IPAddresses": null,
		        "URIs": null,
		        "PermittedDNSDomainsCritical": false,
		        "PermittedDNSDomains": null,
		        "ExcludedDNSDomains": null,
		        "PermittedIPRanges": null,
		        "ExcludedIPRanges": null,
		        "PermittedEmailAddresses": null,
		        "ExcludedEmailAddresses": null,
		        "PermittedURIDomains": null,
		        "ExcludedURIDomains": null,
		        "CRLDistributionPoints": null,
		        "PolicyIdentifiers": null
		    }],
		    "Signature": "J9iQDfXM1GYzIazRH36DUgjeBSp1YIv5gqb0evyrp46mRNdsvGxzBvqVM3K1ZYW530wryweL51oVTbXMEh2PWchQZ7g33Be5lgcl82il7rR5D5tpsiSZ7oZsD4LP+Swv6MoYlKW4hKXWTCY9cWLzJhHkGZPiLsyrWUqdBq/0M8BTyx42/MUmAbYrFVKRjZy8PKsFDAaBcZVbdyZWRqVJy4Lfw8n4P0Ry7bDWRkqhI2rXH4o68eSkNF3KGWzQWXTp6uZb7o5HKc3dn3uoNidKvP3kZaM+XfM9Hd9Cw1MxLwvu1Qdjo6MCOatMKxc02cI7LAA6AsRcYfR+vGkVW3bJP9L29GJ+Dufv7dWcC/xCEG7p6lSYcF86haY/iTwSv/IQoKXQrMnwL8yZpbshJBrdjOzojdZBsJ4/Pu7KdNsnTpR+UvnFdIUrPvYek5WwI8jLz9hTVsSzF0aWCnCf7t8sAaUf90CC04kwGP2jnvZKlNcTQpZ56Zl+n43Z6KkC62do",
		    "TimestampSignature": null
		}
	*/
	ValidSigEnv     = "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9LCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsIm1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5vY2kuaW1hZ2UubWFuaWZlc3QudjEranNvbiIsInNpemUiOjE2NzI0fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3RhcnkuZXhwaXJ5Iiwic2lnbmVkQ3JpdEtleTEiXSwiY3R5IjoiYXBwbGljYXRpb24vdm5kLmNuY2Yubm90YXJ5LnYyLmp3cy52MSIsImlvLmNuY2Yubm90YXJ5LmV4cGlyeSI6IjIwMjItMDYtMjVUMTA6NTY6MjItMDc6MDAiLCJpby5jbmNmLm5vdGFyeS5zaWduaW5nVGltZSI6IjIwMjItMDYtMjRUMTA6NTY6MjItMDc6MDAiLCJzaWduZWRDcml0S2V5MSI6InNpZ25lZFZhbHVlMSIsInNpZ25lZEtleTEiOiJzaWduZWRLZXkyIn0\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"J9iQDfXM1GYzIazRH36DUgjeBSp1YIv5gqb0evyrp46mRNdsvGxzBvqVM3K1ZYW530wryweL51oVTbXMEh2PWchQZ7g33Be5lgcl82il7rR5D5tpsiSZ7oZsD4LP-Swv6MoYlKW4hKXWTCY9cWLzJhHkGZPiLsyrWUqdBq_0M8BTyx42_MUmAbYrFVKRjZy8PKsFDAaBcZVbdyZWRqVJy4Lfw8n4P0Ry7bDWRkqhI2rXH4o68eSkNF3KGWzQWXTp6uZb7o5HKc3dn3uoNidKvP3kZaM-XfM9Hd9Cw1MxLwvu1Qdjo6MCOatMKxc02cI7LAA6AsRcYfR-vGkVW3bJP9L29GJ-Dufv7dWcC_xCEG7p6lSYcF86haY_iTwSv_IQoKXQrMnwL8yZpbshJBrdjOzojdZBsJ4_Pu7KdNsnTpR-UvnFdIUrPvYek5WwI8jLz9hTVsSzF0aWCnCf7t8sAaUf90CC04kwGP2jnvZKlNcTQpZ56Zl-n43Z6KkC62do\"}"
	CorruptedSigEnv = strings.Replace(ValidSigEnv, "0fX0", "1fX0=", 1)
)

type Repository struct {
	ResolveResponse                notation.Descriptor
	ResolveError                   error
	ListSignatureManifestsResponse []registry.SignatureManifest
	ListSignatureManifestsError    error
	GetResponse                    []byte
	GetError                       error
}

func NewRepository() Repository {
	return Repository{
		ResolveResponse: JwsSigEnvDescriptor,
		ListSignatureManifestsResponse: []registry.SignatureManifest{{
			Blob:        JwsSigEnvDescriptor,
			Annotations: Annotations,
		}},
		GetResponse: []byte(ValidSigEnv),
	}
}

func (t Repository) Resolve(ctx context.Context, reference string) (notation.Descriptor, error) {
	return t.ResolveResponse, t.ResolveError
}

func (t Repository) ListSignatureManifests(ctx context.Context, manifestDigest digest.Digest) ([]registry.SignatureManifest, error) {
	return t.ListSignatureManifestsResponse, t.ListSignatureManifestsError
}

func (t Repository) Get(ctx context.Context, digest digest.Digest) ([]byte, error) {
	return t.GetResponse, t.GetError
}

func (t Repository) PutSignatureManifest(ctx context.Context, signature []byte, manifest notation.Descriptor, annotaions map[string]string) (notation.Descriptor, registry.SignatureManifest, error) {
	return notation.Descriptor{}, registry.SignatureManifest{}, nil
}

type PluginManager struct{}

func NewPluginManager() PluginManager {
	return PluginManager{}
}

func (t PluginManager) Get(ctx context.Context, name string) (*manager.Plugin, error) {
	return nil, nil
}
func (t PluginManager) Runner(name string) (plugin.Runner, error) {
	return nil, nil
}
