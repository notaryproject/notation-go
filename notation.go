// Package notation provides signer and verifier for notation Sign
// and Verification.
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
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	orasRegistry "oras.land/oras-go/v2/registry"
)

const annotationX509ChainThumbprint = "io.cncf.notary.x509chain.thumbprint#S256"

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
	logger := log.GetLogger(ctx)

	artifactRef := opts.ArtifactReference
	ref, err := orasRegistry.ParseReference(artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if ref.Reference == "" {
		return ocispec.Descriptor{}, errors.New("reference is missing digest or tag")
	}
	targetDesc, err := repo.Resolve(ctx, artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if ref.ValidateReferenceAsDigest() != nil {
		// artifactRef is not a digest reference
		logger.Warnf("Always sign the artifact using digest(`@sha256:...`) rather than a tag(`:%s`) because tags are mutable and a tag reference can point to a different artifact than the one signed", ref.Reference)
		logger.Infof("Resolved artifact tag `%s` to digest `%s` before signing", ref.Reference, targetDesc.Digest.String())
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

// Verifier is a generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the signature blob and returns the outcome upon
	// successful verification.
	// If nil signature is present and the verification level is not 'skip',
	// an error will be returned.
	Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts VerifyOptions) (*VerificationOutcome, error)
}

// RemoteVerifyOptions contains parameters for notation.Verify.
type RemoteVerifyOptions struct {
	// ArtifactReference is the reference of the artifact that is been
	// verified against to.
	ArtifactReference string

	// PluginConfig is a map of plugin configs.
	PluginConfig map[string]string

	// MaxSignatureAttempts is the maximum number of signature envelopes that
	// will be processed for verification. If set to less than or equals
	// to zero, an error will be returned.
	MaxSignatureAttempts int
}

// Verify performs signature verification on each of the notation supported
// verification types (like integrity, authenticity, etc.) and return the
// successful signature verification outcomes.
// For more details on signature verification, see
// https://github.com/notaryproject/notaryproject/blob/main/specs/trust-store-trust-policy.md#signature-verification
func Verify(ctx context.Context, verifier Verifier, repo registry.Repository, remoteOpts RemoteVerifyOptions) (ocispec.Descriptor, []*VerificationOutcome, error) {
	logger := log.GetLogger(ctx)

	// opts to be passed in verifier.Verify()
	opts := VerifyOptions{
		ArtifactReference: remoteOpts.ArtifactReference,
		PluginConfig:      remoteOpts.PluginConfig,
	}

	// passing nil signature to check 'skip'
	outcome, err := verifier.Verify(ctx, ocispec.Descriptor{}, nil, opts)
	if err != nil {
		if outcome == nil {
			return ocispec.Descriptor{}, nil, err
		}
	} else if reflect.DeepEqual(outcome.VerificationLevel, trustpolicy.LevelSkip) {
		return ocispec.Descriptor{}, []*VerificationOutcome{outcome}, nil
	}

	// check MaxSignatureAttempts
	if remoteOpts.MaxSignatureAttempts <= 0 {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("verifyOptions.MaxSignatureAttempts expects a positive number, got %d", remoteOpts.MaxSignatureAttempts)}
	}

	// get artifact descriptor
	artifactRef := remoteOpts.ArtifactReference
	ref, err := orasRegistry.ParseReference(artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}
	if ref.Reference == "" {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: "reference is missing digest or tag"}
	}
	artifactDescriptor, err := repo.Resolve(ctx, artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}
	if ref.ValidateReferenceAsDigest() != nil {
		// artifactRef is not a digest reference
		logger.Infof("Resolved artifact tag `%s` to digest `%s` before verification", ref.Reference, artifactDescriptor.Digest.String())
		logger.Warn("The resolved digest may not point to the same signed artifact, since tags are mutable")
	}

	var verificationOutcomes []*VerificationOutcome
	errExceededMaxVerificationLimit := ErrorVerificationFailed{Msg: fmt.Sprintf("total number of signatures associated with an artifact should be less than: %d", remoteOpts.MaxSignatureAttempts)}
	numOfSignatureProcessed := 0

	// get signature manifests
	err = repo.ListSignatures(ctx, artifactDescriptor, func(signatureManifests []ocispec.Descriptor) error {
		// process signatures
		for _, sigManifestDesc := range signatureManifests {
			if numOfSignatureProcessed >= remoteOpts.MaxSignatureAttempts {
				break
			}
			numOfSignatureProcessed++
			// get signature envelope
			sigBlob, sigDesc, err := repo.FetchSignatureBlob(ctx, sigManifestDesc)
			if err != nil {
				return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : %v", sigManifestDesc.Digest, artifactRef, err.Error())}
			}
			// using signature media type fetched from registry
			opts.SignatureMediaType = sigDesc.MediaType

			// verify each signature
			outcome, err := verifier.Verify(ctx, artifactDescriptor, sigBlob, opts)
			if err != nil {
				if outcome == nil {
					// TODO: log fatal error
					return err
				}
				continue
			}

			// at this point, the signature is verified successfully. Add
			// it to the verificationOutcomes.
			verificationOutcomes = append(verificationOutcomes, outcome)

			// early break on success
			return errDoneVerification
		}

		if numOfSignatureProcessed >= remoteOpts.MaxSignatureAttempts {
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
	if numOfSignatureProcessed == 0 {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("no signature is associated with %q, make sure the image was signed successfully", artifactRef)}
	}

	// Verification Failed
	if len(verificationOutcomes) == 0 {
		return ocispec.Descriptor{}, verificationOutcomes, ErrorVerificationFailed{}
	}

	// Verification Succeeded
	return artifactDescriptor, verificationOutcomes, nil
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
