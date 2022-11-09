package notation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/timestamp"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verification/trustpolicy"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const annotationX509ChainThumbprint = "io.cncf.notary.x509chain.thumbprint#S256"

// Descriptor describes the artifact that needs to be signed.
type Descriptor struct {
	// The media type of the targeted content.
	MediaType string `json:"mediaType"`

	// The digest of the targeted content.
	Digest digest.Digest `json:"digest"`

	// Specifies the size in bytes of the blob.
	Size int64 `json:"size"`

	// Contains optional user defined attributes.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Equal reports whether d and t points to the same content.
func (d Descriptor) Equal(t Descriptor) bool {
	return d.MediaType == t.MediaType && d.Digest == t.Digest && d.Size == t.Size && reflect.DeepEqual(d.Annotations, t.Annotations)
}

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

	// TSA is the TimeStamp Authority to timestamp the resulted signature if
	// present.
	TSA timestamp.Timestamper

	// TSAVerifyOptions is the verify option to verify the fetched timestamp
	// signature.
	// The `Intermediates` in the verify options will be ignored and
	// re-contrusted using the certificates in the fetched timestamp signature.
	// An empty list of `KeyUsages` in the verify options implies
	// ExtKeyUsageTimeStamping.
	TSAVerifyOptions x509.VerifyOptions

	// Sets or overrides the plugin configuration.
	PluginConfig map[string]string
}

// Payload describes the content that gets signed.
type payload struct {
	TargetArtifact Descriptor `json:"targetArtifact"`
}

// Signer is a generic interface for signing an artifact.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type Signer interface {
	// Sign signs the artifact described by its descriptor,
	// and returns the signature and SignerInfo.
	Sign(ctx context.Context, desc Descriptor, envelopeMediaType string, opts SignOptions) ([]byte, *signature.SignerInfo, error)
}

// Sign signs the artifact in the remote registry and push the signature to the
// remote.
// The descriptor of the sign content is returned upon sucessful signing.
func Sign(ctx context.Context, signer Signer, repo registry.Repository, opts SignOptions) (Descriptor, error) {
	ociDesc, err := repo.Resolve(ctx, opts.ArtifactReference)
	if err != nil {
		return Descriptor{}, err
	}
	desc := notationDescriptorFromOCI(ociDesc)
	sig, signerInfo, err := signer.Sign(ctx, desc, opts.SignatureMediaType, opts)
	if err != nil {
		return Descriptor{}, err
	}
	annotations, err := generateAnnotations(signerInfo)
	if err != nil {
		return Descriptor{}, err
	}
	_, _, err = repo.PushSignature(ctx, sig, opts.SignatureMediaType, ociDesc, annotations)
	if err != nil {
		return Descriptor{}, err
	}

	return desc, nil
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

	// VerificationLevel encapsulates the signature verification preset and its
	// actions for each verification type
	VerificationLevel *trustpolicy.VerificationLevel
}

// ValidationResult encapsulates the verification result (passed or failed)
// for a verification type, including the desired verification action as
//
//	specified in the trust policy
type ValidationResult struct {
	// Success is set to true if the verification was successful
	Success bool
	// Type of verification that is performed
	Type trustpolicy.ValidationType
	// Action is the intended action for the given verification type as defined
	// in the trust policy
	Action trustpolicy.ValidationAction
	// Err is set if there are any errors during the verification process
	Error error
}

// VerificationOutcome encapsulates a signature blob's descriptor, its content,
// the verification level and results for each verification type that was
// performed.
type VerificationOutcome struct {
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
	// Verify verifies the signature blob and returns the signature blob
	// descriptor upon successful verification.
	Verify(ctx context.Context, signature []byte, opts VerifyOptions) (Descriptor, *VerificationOutcome, error)

	// TrustPolicyDocument gets the validated trust policy document.
	TrustPolicyDocument() (*trustpolicy.Document, error)
}

/*
Verify performs signature verification on each of the notation supported
verification types (like integrity, authenticity, etc.) and return the
verification outcomes.

Given an artifact reference, Verify will retrieve all the signatures associated
with the reference and perform signature verification.
A signature is considered not valid if verification fails due to any one of the
following reasons

 1. Artifact Reference is not associated with a signature i.e. unsigned
 2. Registry is unavailable to retrieve the signature
 3. Signature does not satisfy the verification rules configured in the trust
    policy
 4. Signature specifies a plugin for extended verification and that throws an
    error
 5. Digest in the signature does not match the digest present in the reference

If each and every signature associated with the reference fail the verification,
then Verify will return `ErrorVerificationFailed` error along with an array
of `VerificationOutcome`.

# Callers can pass the verification plugin config in VerifyOptions.PluginConfig

For more details on signature verification, see https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#signature-verification
*/
func Verify(ctx context.Context, verifier Verifier, repo registry.Repository, opts VerifyOptions) (Descriptor, []*VerificationOutcome, error) {
	var verificationOutcomes []*VerificationOutcome
	artifactRef := opts.ArtifactReference
	artifactDescriptor, err := repo.Resolve(ctx, artifactRef)
	if err != nil {
		return Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}

	trustpolicyDoc, err := verifier.TrustPolicyDocument()
	if err != nil {
		return Descriptor{}, nil, ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	trustPolicy, err := trustpolicyDoc.GetApplicableTrustPolicy(artifactRef)
	if err != nil {
		return Descriptor{}, nil, ErrorNoApplicableTrustPolicy{Msg: err.Error()}
	}
	// ignore the error since we already validated the policy document
	verificationLevel, _ := trustPolicy.SignatureVerification.GetVerificationLevel()
	if verificationLevel.Name == trustpolicy.LevelSkip.Name {
		verificationOutcomes = append(verificationOutcomes, &VerificationOutcome{VerificationLevel: verificationLevel})
		return Descriptor{}, verificationOutcomes, nil
	}
	opts.VerificationLevel = verificationLevel

	// get signature manifests
	var success bool
	var verifiedSigBlobDesc ocispec.Descriptor
	err = repo.ListSignatures(ctx, artifactDescriptor, func(signatureManifests []ocispec.Descriptor) error {
		if len(signatureManifests) < 1 {
			return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("no signatures are associated with %q, make sure the image was signed successfully", artifactRef)}
		}
		// if already verified successfully, no need to continue
		if success {
			return nil
		}
		// process signatures
		for _, sigManifest := range signatureManifests {
			// get signature envelope
			sigBlob, sigBlobDesc, err := repo.FetchSignatureBlob(ctx, sigManifest)
			if err != nil {
				return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the registry, error : %s", sigBlobDesc.Digest, artifactRef, err.Error())}
			}
			_, outcome, err := verifier.Verify(ctx, sigBlob, opts)
			if err != nil {
				if outcome != nil && outcome.Error != nil {
					outcome.SignatureBlobDescriptor = &sigBlobDesc
					verificationOutcomes = append(verificationOutcomes, outcome)
				}
				continue
			}
			outcome.SignatureBlobDescriptor = &sigBlobDesc
			verificationOutcomes = append(verificationOutcomes, outcome)

			// artifact digest must match the digest from the signature payload
			payload := &payload{}
			err = json.Unmarshal(outcome.EnvelopeContent.Payload.Content, payload)
			if err != nil || !notationDescriptorFromOCI(artifactDescriptor).Equal(payload.TargetArtifact) {
				outcome.Error = fmt.Errorf("given digest %q does not match the digest %q present in the digital signature", artifactDescriptor.Digest.String(), payload.TargetArtifact.Digest.String())
				continue
			}
			outcome.SignedAnnotations = payload.TargetArtifact.Annotations

			// At this point, we've found a signature verified successfully
			success = true
			// Descriptor of the signature blob that get verified successfully
			verifiedSigBlobDesc = sigBlobDesc

			return nil
		}
		return nil
	})

	if err != nil {
		return Descriptor{}, nil, err
	}

	// check whether verification was successful or not
	if success {
		// signature verification succeeds if there is at least one good
		// signature
		return notationDescriptorFromOCI(verifiedSigBlobDesc), verificationOutcomes, nil
	}

	return Descriptor{}, verificationOutcomes, ErrorVerificationFailed{}
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

func notationDescriptorFromOCI(desc ocispec.Descriptor) Descriptor {
	return Descriptor{
		MediaType:   desc.MediaType,
		Digest:      desc.Digest,
		Size:        desc.Size,
		Annotations: desc.Annotations,
	}
}
