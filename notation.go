package notation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verification/trustpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

const annotationX509ChainThumbprint = "io.cncf.notary.x509chain.thumbprint#S256"

const maxVerificationLimitDefault = 50

var errDoneVerification = errors.New("done verification")

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
	Sign(ctx context.Context, desc ocispec.Descriptor, opts SignOptions) ([]byte, *signature.SignerInfo, error)
}

// Sign signs the artifact in the remote registry and push the signature to the
// remote.
// The descriptor of the sign content is returned upon sucessful signing.
func Sign(ctx context.Context, signer Signer, repo registry.Repository, opts SignOptions) (ocispec.Descriptor, error) {
	targetDesc, err := repo.Resolve(ctx, opts.ArtifactReference)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	sig, signerInfo, err := signer.Sign(ctx, targetDesc, opts)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	annotations, err := generateAnnotations(signerInfo)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	_, _, err = repo.PushSignature(ctx, opts.SignatureMediaType, sig, targetDesc, annotations)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	return targetDesc, nil
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

	// MaxSignatureAttempts is the maximum number of signature envelopes that
	// can be associated with the target artifact. If set to less than or equals
	// to zero, value defaults to 50.
	// Note: this option is scoped to notation.Verify(). verifier.Verify() is
	// for signle signature verification, and therefore, does not use it.
	MaxSignatureAttempts int
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
	// RawSignature is the signature envelope blob
	RawSignature []byte

	// EnvelopeContent contains the details of the digital signature and
	// associated metadata
	EnvelopeContent *signature.EnvelopeContent

	// VerificationLevel describes what verification level was used for
	// performing signature verification
	VerificationLevel *trustpolicy.VerificationLevel

	// VerificationResults contains the verifications performed on the signature
	// and their results
	VerificationResults []*ValidationResult

	// Error that caused the verification to fail (if it fails)
	Error error
}

// Verifier is a generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the signature blob and returns the artifact
	// descriptor upon successful verification.
	// If nil signature is present and the verification level is not 'skip',
	// an error will be returned.
	Verify(ctx context.Context, signature []byte, opts VerifyOptions) (ocispec.Descriptor, *VerificationOutcome, error)
}

// Verify performs signature verification on each of the notation supported
// verification types (like integrity, authenticity, etc.) and return the
// verification outcomes.
// For more details on signature verification, see
// https://github.com/notaryproject/notaryproject/blob/main/specs/trust-store-trust-policy.md#signature-verification
func Verify(ctx context.Context, verifier Verifier, repo registry.Repository, opts VerifyOptions) (ocispec.Descriptor, []*VerificationOutcome, error) {
	// passing nil signature to check 'skip'
	_, outcome, err := verifier.Verify(ctx, nil, opts)
	if err != nil {
		if outcome == nil {
			return ocispec.Descriptor{}, nil, err
		}
	} else if reflect.DeepEqual(outcome.VerificationLevel, trustpolicy.LevelSkip) {
		return ocispec.Descriptor{}, []*VerificationOutcome{outcome}, nil
	}
	// get signature manifests
	artifactRef := opts.ArtifactReference
	artifactDescriptor, err := repo.Resolve(ctx, artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}

	var verificationOutcomes []*VerificationOutcome
	var targetArtifactDesc ocispec.Descriptor
	if opts.MaxSignatureAttempts <= 0 {
		// Set MaxVerificationLimit to 50 as default
		opts.MaxSignatureAttempts = maxVerificationLimitDefault
	}
	errExceededMaxVerificationLimit := ErrorVerificationFailed{Msg: fmt.Sprintf("total number of signatures associated with an artifact should be less than: %d", opts.MaxSignatureAttempts)}
	count := 0
	err = repo.ListSignatures(ctx, artifactDescriptor, func(signatureManifests []ocispec.Descriptor) error {
		// process signatures
		for _, sigManifestDesc := range signatureManifests {
			if count >= opts.MaxSignatureAttempts {
				break
			}
			count++
			// get signature envelope
			sigBlob, _, err := repo.FetchSignatureBlob(ctx, sigManifestDesc)
			if err != nil {
				return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : %v", sigManifestDesc.Digest, artifactRef, err.Error())}
			}
			payloadArtifactDescriptor, outcome, err := verifier.Verify(ctx, sigBlob, opts)
			if err != nil {
				if outcome == nil {
					// TODO: log fatal error
					return err
				}
				verificationOutcomes = append(verificationOutcomes, outcome)
				continue
			}
			if !content.Equal(payloadArtifactDescriptor, artifactDescriptor) {
				outcome.Error = errors.New("content descriptor mismatch")
				verificationOutcomes = append(verificationOutcomes, outcome)
				continue
			}

			//
			if !equal(&targetArtifactDescriptor, &artifactDescriptor) {
				outcome.SignatureBlobDescriptor = &sigBlobDesc
				outcome.Error = err
				verificationOutcomes = append(verificationOutcomes, outcome)
				continue
			}

			// At this point, we've found a signature verified successfully
			verificationOutcomes = append(verificationOutcomes, outcome)
			// Descriptor of the signature blob that gets verified successfully
			targetArtifactDesc = payloadArtifactDescriptor

			return errDoneVerification
		}

		if count >= opts.MaxSignatureAttempts {
			return errExceededMaxVerificationLimit
		}

		return nil
	})

	if err != nil && !errors.Is(err, errDoneVerification) {
		if errors.Is(err, errExceededMaxVerificationLimit) {
			return ocispec.Descriptor{}, verificationOutcomes, err
		}
		return ocispec.Descriptor{}, nil, err
	}

	// If there's no signature associated with the reference
	if len(verificationOutcomes) == 0 {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("no signature is associated with %q, make sure the image was signed successfully", artifactRef)}
	}

	// check whether verification was successful or not
	if verificationOutcomes[len(verificationOutcomes)-1].Error != nil {
		return ocispec.Descriptor{}, verificationOutcomes, ErrorVerificationFailed{}
	}

	return targetArtifactDesc, verificationOutcomes, nil
}

func generateAnnotations(signerInfo *signature.SignerInfo) (map[string]string, error) {
	var thumbprints []string
	for _, cert := range signerInfo.CertificateChain {
		checkSum := sha256.Sum256(cert.Raw)
		thumbprints = append(thumbprints, hex.EncodeToString(checkSum[:]))
	}
	val, err := json.Marshal(thumbprints)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		annotationX509ChainThumbprint: string(val),
	}, nil
}
