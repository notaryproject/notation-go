package verification

type Verifier struct {
	PolicyDocument  *PolicyDocument
	X509TrustStores []*X509TrustStore
}

func NewVerifier(policyDocument *PolicyDocument, x509TrustStores []*X509TrustStore) *Verifier {
	return &Verifier{
		PolicyDocument:  policyDocument,
		X509TrustStores: x509TrustStores,
	}
}

func (v *Verifier) Verify(artifactUri string) error {
	/*
		[DONE] Find the applicable trust policy, if none, return error
		If signatureVerification is skip, then return without an error
		Retrieve signature manifests
		Return error if no signature manifests
		For each signature manifest
			Check the root cert hash is present in trust store hashes, otherwise fail early
			Retrieve the signature envelope
			Verify integrity
				Signing cert produced the signature
				Chain from signing cert to root cert is valid
			Verify Authenticity
				[DONE] Verify root of trust is established
				[DONE] Verify trusted identites match from the policy
			Verify expiry time of the signature is in the future
			(NOT in RC1) Verify timestamping signature if present
			(NOT in RC1) Verify revocation
			Invoke plugin for extended verification
	*/

	// No error
	return nil
}
