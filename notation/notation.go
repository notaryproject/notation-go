package notation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const annotationX509ChainThumbprint = "io.cncf.notary.x509chain.thumbprint#S256"

// SignOptions contains parameters for Signer.Sign.
type SignOptions struct {
	// Reference of the artifact that needs to be signed.
	ArtifactReference string

	// SignatureMediaType is the envelope type of the signature.
	// Currently both `application/jose+json` and `application/cose` are
	// supported.
	SignatureMediaType string

	// Expiry identifies the expiration time of the resulted signature.
	Expiry time.Time

	// Sets or overrides the plugin configuration.
	PluginConfig map[string]string
}

// Signer is a generic interface for signing an artifact.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type Signer interface {
	// Sign signs the artifact described by its descriptor,
	// and returns the signature and SignerInfo.
	Sign(ctx context.Context, desc ocispec.Descriptor, envelopeMediaType string, opts SignOptions) ([]byte, *signature.SignerInfo, error)
}

// Sign signs the artifact in the remote registry and push the signature to the
// remote.
// The descriptor of the sign content is returned upon sucessful signing.
func Sign(ctx context.Context, signer Signer, repo registry.Repository, opts SignOptions) (ocispec.Descriptor, error) {
	ociDesc, err := repo.Resolve(ctx, opts.ArtifactReference)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	sig, signerInfo, err := signer.Sign(ctx, ociDesc, opts.SignatureMediaType, opts)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	annotations, err := generateAnnotations(signerInfo)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	_, _, err = repo.PushSignature(ctx, sig, opts.SignatureMediaType, ociDesc, annotations)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	return ociDesc, nil
}

// VerifyOptions contains parameters for Verifier.Verify.
type VerifyOptions struct {
	// ArtifactReference is the reference of the artifact that is been
	// verified against to.
	ArtifactReference string

	// SignatureMediaType is the envelope type of the signature.
	// Currently both `application/jose+json` and `application/cose` are
	// supported.
	SignatureMediaType string

	// PluginConfig is a map of plugin configs.
	PluginConfig map[string]string
}

// ValidationResult encapsulates the verification result (passed or failed)
// for a verification type, including the desired verification action as
// specified in the trust policy
type ValidationResult struct {
	// Type of verification that is performed
	Type trustpolicy.ValidationType

	// Action is the intended action for the given verification type as defined
	// in the trust policy
	Action trustpolicy.ValidationAction

	// Error is set if there are any errors during the verification process
	Error error
}

// VerificationOutcome encapsulates a signature blob's descriptor, its content,
// the verification level and results for each verification type that was
// performed.
type VerificationOutcome struct {
	// SignatureBlobDescriptor is descriptor of the signature envelope blob
	SignatureBlobDescriptor *ocispec.Descriptor

	// EnvelopeContent contains the details of the digital signature and
	// associated metadata
	EnvelopeContent *signature.EnvelopeContent

	// VerificationLevel describes what verification level was used for
	// performing signature verification
	VerificationLevel *trustpolicy.VerificationLevel

	// VerificationResults contains the verifications performed on the signature
	// and their results
	VerificationResults []*ValidationResult

	// SignedAnnotations contains arbitrary metadata relating to the target
	// artifact that was signed
	SignedAnnotations map[string]string

	// Error that caused the verification to fail (if it fails)
	Error error
}

// Verifier is a generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the signature blob and returns the artifact
	// descriptor upon successful verification.
	Verify(ctx context.Context, signature []byte, opts VerifyOptions) (ocispec.Descriptor, *VerificationOutcome, error)
}

// Verify performs signature verification on each of the notation supported
// verification types (like integrity, authenticity, etc.) and return the
// verification outcomes.
// For more details on signature verification, see
// https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#signature-verification
func Verify(ctx context.Context, verifier Verifier, repo registry.Repository, opts VerifyOptions) (ocispec.Descriptor, []*VerificationOutcome, error) {
	var verificationOutcomes []*VerificationOutcome
	artifactRef := opts.ArtifactReference
	// passing nil signature to check 'skip'
	_, outcome, err := verifier.Verify(ctx, nil, opts)
	if outcome == nil {
		return ocispec.Descriptor{}, nil, err
	}
	verificationLevel := outcome.VerificationLevel
	if verificationLevel.Name == trustpolicy.LevelSkip.Name {
		verificationOutcomes = append(verificationOutcomes, &VerificationOutcome{VerificationLevel: verificationLevel})
		return ocispec.Descriptor{}, verificationOutcomes, nil
	}

	// get signature manifests
	var success bool
	doneVerification := errors.New("done verification")
	var verifiedSigBlobDesc ocispec.Descriptor
	artifactDescriptor, err := repo.Resolve(ctx, artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}
	err = repo.ListSignatures(ctx, artifactDescriptor, func(signatureManifests []ocispec.Descriptor) error {
		// if already verified successfully, no need to continue
		if success {
			return nil
		}

		if len(signatureManifests) < 1 {
			return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", artifactRef)}
		}

		// process signatures
		for _, sigManifest := range signatureManifests {
			// get signature envelope
			sigBlob, sigBlobDesc, err := repo.FetchSignatureBlob(ctx, sigManifest)
			if err != nil {
				return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : %s", sigBlobDesc.Digest, artifactRef, err.Error())}
			}
			payloadArtifactDescriptor, outcome, err := verifier.Verify(ctx, sigBlob, opts)
			if err == nil && !equal(&payloadArtifactDescriptor, &artifactDescriptor) {
				err = errors.New("payloadArtifactDescriptor does not match artifactDescriptor")
			}
			if err != nil {
				if outcome != nil {
					outcome.SignatureBlobDescriptor = &sigBlobDesc
					outcome.Error = err
					verificationOutcomes = append(verificationOutcomes, outcome)
				}
				continue
			}

			// At this point, we've found a signature verified successfully
			outcome.SignatureBlobDescriptor = &sigBlobDesc
			verificationOutcomes = append(verificationOutcomes, outcome)
			success = true
			// Descriptor of the signature blob that gets verified successfully
			verifiedSigBlobDesc = sigBlobDesc

			return doneVerification
		}
		return nil
	})

	if err != nil && !errors.Is(err, doneVerification) {
		return ocispec.Descriptor{}, nil, err
	}

	// check whether verification was successful or not
	if success {
		// signature verification succeeds if there is at least one good
		// signature
		return verifiedSigBlobDesc, verificationOutcomes, nil
	}

	return ocispec.Descriptor{}, verificationOutcomes, ErrorVerificationFailed{}
}

func generateAnnotations(signerInfo *signature.SignerInfo) (map[string]string, error) {
	annotations := make(map[string]string)
	var thumbprints []string
	certChain := signerInfo.CertificateChain
	for _, cert := range certChain {
		checkSum := sha256.Sum256(cert.Raw)
		thumbprints = append(thumbprints, strings.ToLower(hex.EncodeToString(checkSum[:])))
	}
	val, err := json.Marshal(thumbprints)
	if err != nil {
		return nil, err
	}
	annotations[annotationX509ChainThumbprint] = string(val)

	return annotations, nil
}

// Equal reports whether d and t points to the same content.
func equal(d *ocispec.Descriptor, t *ocispec.Descriptor) bool {
	return d.MediaType == t.MediaType &&
		d.Digest == t.Digest &&
		d.Size == t.Size &&
		reflect.DeepEqual(d.Annotations, t.Annotations)
}
