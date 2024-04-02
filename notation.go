// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"io"
	"mime"
	"strings"
	"time"

	orasRegistry "oras.land/oras-go/v2/registry"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var errDoneVerification = errors.New("done verification")
var reservedAnnotationPrefixes = [...]string{"io.cncf.notary"}

// SignerSignOptions contains parameters for Signer.Sign.
type SignerSignOptions struct {
	// SignatureMediaType is the envelope type of the signature.
	// Currently, both `application/jose+json` and `application/cose` are
	// supported.
	SignatureMediaType string

	// ExpiryDuration identifies the expiry duration of the resulted signature.
	// Zero value represents no expiry duration.
	ExpiryDuration time.Duration

	// PluginConfig sets or overrides the plugin configuration.
	PluginConfig map[string]string

	// SigningAgent sets the signing agent name
	SigningAgent string
}

// Signer is a generic interface for signing an OCI artifact.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type Signer interface {
	// Sign signs the OCI artifact described by its descriptor,
	// and returns the signature and SignerInfo.
	Sign(ctx context.Context, desc ocispec.Descriptor, opts SignerSignOptions) ([]byte, *signature.SignerInfo, error)
}

// SignBlobOptions contains parameters for notation.SignBlob.
type SignBlobOptions struct {
	SignerSignOptions
	// ContentMediaType is the media-type of the blob being signed.
	ContentMediaType string
	// UserMetadata contains key-value pairs that are added to the signature
	// payload
	UserMetadata map[string]string
}

// BlobDescriptorGenerator creates descriptor using the digest Algorithm.
type BlobDescriptorGenerator func(digest.Algorithm) (ocispec.Descriptor, error)

// BlobSigner is a generic interface for signing arbitrary data.
// The interface allows signing with local or remote keys,
// and packing in various signature formats.
type BlobSigner interface {
	// SignBlob signs the descriptor returned by genDesc ,
	// and returns the signature and SignerInfo
	SignBlob(ctx context.Context, genDesc BlobDescriptorGenerator, opts SignerSignOptions) ([]byte, *signature.SignerInfo, error)
}

// signerAnnotation facilitates return of manifest annotations by signers
type signerAnnotation interface {
	// PluginAnnotations returns signature manifest annotations returned from
	// plugin
	PluginAnnotations() map[string]string
}

// SignOptions contains parameters for notation.Sign.
type SignOptions struct {
	SignerSignOptions

	// ArtifactReference sets the reference of the artifact that needs to be
	// signed. It can be a tag, a digest or a full reference.
	ArtifactReference string

	// UserMetadata contains key-value pairs that are added to the signature
	// payload
	UserMetadata map[string]string
}

// Sign signs the OCI artifact and push the signature to the Repository.
// The descriptor of the sign content is returned upon successful signing.
func Sign(ctx context.Context, signer Signer, repo registry.Repository, signOpts SignOptions) (ocispec.Descriptor, error) {
	// sanity check
	if err := validateSignArguments(signer, signOpts.SignerSignOptions); err != nil {
		return ocispec.Descriptor{}, err
	}
	if repo == nil {
		return ocispec.Descriptor{}, errors.New("repo cannot be nil")
	}

	logger := log.GetLogger(ctx)
	artifactRef := signOpts.ArtifactReference
	if ref, err := orasRegistry.ParseReference(artifactRef); err == nil {
		// artifactRef is a valid full reference
		artifactRef = ref.Reference
	}
	targetDesc, err := repo.Resolve(ctx, artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to resolve reference: %w", err)
	}
	// artifactRef is a tag or a digest, if it's a digest it has to match
	// the resolved digest
	if artifactRef != targetDesc.Digest.String() {
		if _, err := digest.Parse(artifactRef); err == nil {
			// artifactRef is a digest, but does not match the resolved digest
			return ocispec.Descriptor{}, fmt.Errorf("user input digest %s does not match the resolved digest %s", artifactRef, targetDesc.Digest.String())
		}
		// artifactRef is a tag
		logger.Warnf("Always sign the artifact using digest(`@sha256:...`) rather than a tag(`:%s`) because tags are mutable and a tag reference can point to a different artifact than the one signed", artifactRef)
		logger.Infof("Resolved artifact tag `%s` to digest `%s` before signing", artifactRef, targetDesc.Digest.String())
	}
	descToSign, err := addUserMetadataToDescriptor(ctx, targetDesc, signOpts.UserMetadata)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	sig, signerInfo, err := signer.Sign(ctx, descToSign, signOpts.SignerSignOptions)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	var pluginAnnotations map[string]string
	if signerAnts, ok := signer.(signerAnnotation); ok {
		pluginAnnotations = signerAnts.PluginAnnotations()
	}

	logger.Debug("Generating annotation")
	annotations, err := generateAnnotations(signerInfo, pluginAnnotations)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	logger.Debugf("Generated annotations: %+v", annotations)
	logger.Debugf("Pushing signature of artifact descriptor: %+v, signature media type: %v", targetDesc, signOpts.SignatureMediaType)
	_, _, err = repo.PushSignature(ctx, signOpts.SignatureMediaType, sig, targetDesc, annotations)
	if err != nil {
		logger.Error("Failed to push the signature")
		return ocispec.Descriptor{}, ErrorPushSignatureFailed{Msg: err.Error()}
	}

	return targetDesc, nil
}

// SignBlob signs the arbitrary data and returns the signature
func SignBlob(ctx context.Context, signer BlobSigner, blobReader io.Reader, signBlobOpts SignBlobOptions) ([]byte, *signature.SignerInfo, error) {
	// sanity checks
	if err := validateSignArguments(signer, signBlobOpts.SignerSignOptions); err != nil {
		return nil, nil, err
	}

	if blobReader == nil {
		return nil, nil, errors.New("blobReader cannot be nil")
	}

	if signBlobOpts.ContentMediaType == "" {
		return nil, nil, errors.New("content media-type cannot be empty")
	}

	if err := validateContentType(signBlobOpts.ContentMediaType); err != nil {
		return nil, nil, err
	}

	getDescFunc := getDescriptorFunc(ctx, blobReader, signBlobOpts.ContentMediaType, signBlobOpts.UserMetadata)
	return signer.SignBlob(ctx, getDescFunc, signBlobOpts.SignerSignOptions)
}

func validateSignArguments(signer any, signOpts SignerSignOptions) error {
	if signer == nil {
		return errors.New("signer cannot be nil")
	}
	if signOpts.ExpiryDuration < 0 {
		return errors.New("expiry duration cannot be a negative value")
	}
	if signOpts.ExpiryDuration%time.Second != 0 {
		return errors.New("expiry duration supports minimum granularity of seconds")
	}
	if signOpts.SignatureMediaType == "" {
		return errors.New("signature media-type cannot be empty")
	}
	if err := validateSigMediaType(signOpts.SignatureMediaType); err != nil {
		return err
	}

	return nil
}

func addUserMetadataToDescriptor(ctx context.Context, desc ocispec.Descriptor, userMetadata map[string]string) (ocispec.Descriptor, error) {
	logger := log.GetLogger(ctx)

	if desc.Annotations == nil && len(userMetadata) > 0 {
		desc.Annotations = map[string]string{}
	}

	for k, v := range userMetadata {
		logger.Debugf("Adding metadata %v=%v to annotations", k, v)

		for _, reservedPrefix := range reservedAnnotationPrefixes {
			if strings.HasPrefix(k, reservedPrefix) {
				return desc, fmt.Errorf("error adding user metadata: metadata key %v has reserved prefix %v", k, reservedPrefix)
			}
		}

		if _, ok := desc.Annotations[k]; ok {
			return desc, fmt.Errorf("error adding user metadata: metadata key %v is already present in the target artifact", k)
		}

		desc.Annotations[k] = v
	}

	return desc, nil
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

// VerificationOutcome encapsulates a signature envelope blob, its content,
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

func (outcome *VerificationOutcome) UserMetadata() (map[string]string, error) {
	if outcome.EnvelopeContent == nil {
		return nil, errors.New("unable to find envelope content for verification outcome")
	}

	var payload envelope.Payload
	err := json.Unmarshal(outcome.EnvelopeContent.Payload.Content, &payload)
	if err != nil {
		return nil, errors.New("failed to unmarshal the payload content in the signature blob to envelope.Payload")
	}

	if payload.TargetArtifact.Annotations == nil {
		return map[string]string{}, nil
	}

	return payload.TargetArtifact.Annotations, nil
}

// VerifierVerifyOptions contains parameters for Verifier.Verify.
type VerifierVerifyOptions struct {
	// ArtifactReference is the reference of the artifact that is being
	// verified against to. It must be a full reference.
	ArtifactReference string

	// SignatureMediaType is the envelope type of the signature.
	// Currently only `application/jose+json` and `application/cose` are
	// supported.
	SignatureMediaType string

	// PluginConfig is a map of plugin configs.
	PluginConfig map[string]string

	// UserMetadata contains key-value pairs that must be present in the
	// signature.
	UserMetadata map[string]string
}

// Verifier is a generic interface for verifying an artifact.
type Verifier interface {
	// Verify verifies the signature blob `signature` against the target OCI
	// artifact with manifest descriptor `desc`, and returns the outcome upon
	// successful verification.
	// If nil signature is present and the verification level is not 'skip',
	// an error will be returned.
	Verify(ctx context.Context, desc ocispec.Descriptor, signature []byte, opts VerifierVerifyOptions) (*VerificationOutcome, error)
}

// BlobVerifierVerifyOptions contains parameters for Verifier.Verify.
type BlobVerifierVerifyOptions struct {
	// SignatureMediaType is the envelope type of the signature.
	// Currently only `application/jose+json` and `application/cose` are
	// supported.
	SignatureMediaType string

	// PluginConfig is a map of plugin configs.
	PluginConfig map[string]string

	// UserMetadata contains key-value pairs that must be present in the
	// signature.
	UserMetadata map[string]string

	// TrustPolicyName is the name of trust policy picked by caller.
	// If empty, the global trust policy will be used.
	// This is mainly for non-CLI notation-go users, who do not have a UI to
	// specify trust policy name directly.
	TrustPolicyName string
}

// BlobVerifier is a generic interface for verifying an artifact.
type BlobVerifier interface {
	// VerifyBlob verifies the signature blob `signature` against the target OCI
	// artifact with manifest descriptor `desc`, and returns the outcome upon
	// successful verification.
	// If nil signature is present and the verification level is not 'skip',
	// an error will be returned.
	VerifyBlob(ctx context.Context, descGenFunc BlobDescriptorGenerator, signature []byte, opts BlobVerifierVerifyOptions) (*VerificationOutcome, error)
}

type verifySkipper interface {
	// SkipVerify validates whether the verification level is skip.
	SkipVerify(ctx context.Context, opts VerifierVerifyOptions) (bool, *trustpolicy.VerificationLevel, error)
}

// VerifyOptions contains parameters for notation.Verify.
type VerifyOptions struct {
	// ArtifactReference is the reference of the artifact that is being
	// verified against to.
	ArtifactReference string

	// PluginConfig is a map of plugin configs.
	PluginConfig map[string]string

	// MaxSignatureAttempts is the maximum number of signature envelopes that
	// will be processed for verification. If set to less than or equals
	// to zero, an error will be returned.
	MaxSignatureAttempts int

	// UserMetadata contains key-value pairs that must be present in the
	// signature
	UserMetadata map[string]string
}

type VerifyBlobOptions struct {
	BlobVerifierVerifyOptions

	// ContentMediaType is the media-type type of the content being verified.
	ContentMediaType string
}

func VerifyBlob(ctx context.Context, blobVerifier BlobVerifier, blobReader io.Reader, signature []byte, verifyBlobOpts VerifyBlobOptions) (ocispec.Descriptor, *VerificationOutcome, error) {
	if blobVerifier == nil {
		return ocispec.Descriptor{}, nil, errors.New("blobVerifier cannot be nil")
	}

	if blobReader == nil {
		return ocispec.Descriptor{}, nil, errors.New("blobReader cannot be nil")
	}

	if signature == nil || len(signature) == 0 {
		return ocispec.Descriptor{}, nil, errors.New("blobReader cannot be nil or empty")
	}

	if err := validateContentType(verifyBlobOpts.ContentMediaType); err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	if err := validateSigMediaType(verifyBlobOpts.SignatureMediaType); err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	getDescFunc := getDescriptorFunc(ctx, blobReader, verifyBlobOpts.ContentMediaType, verifyBlobOpts.UserMetadata)
	vo, err := blobVerifier.VerifyBlob(ctx, getDescFunc, signature, verifyBlobOpts.BlobVerifierVerifyOptions)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	var desc ocispec.Descriptor
	if err = json.Unmarshal(vo.EnvelopeContent.Payload.Content, &desc); err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	return desc, vo, nil
}

// Verify performs signature verification on each of the notation supported
// verification types (like integrity, authenticity, etc.) and return the
// successful signature verification outcome.
// For more details on signature verification, see
// https://github.com/notaryproject/notaryproject/blob/main/specs/trust-store-trust-policy.md#signature-verification
func Verify(ctx context.Context, verifier Verifier, repo registry.Repository, verifyOpts VerifyOptions) (ocispec.Descriptor, []*VerificationOutcome, error) {
	logger := log.GetLogger(ctx)

	// sanity check
	if verifier == nil {
		return ocispec.Descriptor{}, nil, errors.New("verifier cannot be nil")
	}
	if repo == nil {
		return ocispec.Descriptor{}, nil, errors.New("repo cannot be nil")
	}
	if verifyOpts.MaxSignatureAttempts <= 0 {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("verifyOptions.MaxSignatureAttempts expects a positive number, got %d", verifyOpts.MaxSignatureAttempts)}
	}

	// opts to be passed in verifier.Verify()
	opts := VerifierVerifyOptions{
		ArtifactReference: verifyOpts.ArtifactReference,
		PluginConfig:      verifyOpts.PluginConfig,
		UserMetadata:      verifyOpts.UserMetadata,
	}

	if skipChecker, ok := verifier.(verifySkipper); ok {
		logger.Info("Checking whether signature verification should be skipped or not")
		skip, verificationLevel, err := skipChecker.SkipVerify(ctx, opts)
		if err != nil {
			return ocispec.Descriptor{}, nil, err
		}
		if skip {
			logger.Infoln("Verification skipped for", verifyOpts.ArtifactReference)
			return ocispec.Descriptor{}, []*VerificationOutcome{{VerificationLevel: verificationLevel}}, nil
		}
		logger.Info("Check over. Trust policy is not configured to skip signature verification")
	}

	// get artifact descriptor
	artifactRef := verifyOpts.ArtifactReference
	ref, err := orasRegistry.ParseReference(artifactRef)
	if err != nil {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}
	if ref.Reference == "" {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: "reference is missing digest or tag"}
	}
	artifactDescriptor, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: err.Error()}
	}
	if ref.ValidateReferenceAsDigest() != nil {
		// artifactRef is not a digest reference
		logger.Infof("Resolved artifact tag `%s` to digest `%s` before verification", ref.Reference, artifactDescriptor.Digest.String())
		logger.Warn("The resolved digest may not point to the same signed artifact, since tags are mutable")
	} else if ref.Reference != artifactDescriptor.Digest.String() {
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("user input digest %s does not match the resolved digest %s", ref.Reference, artifactDescriptor.Digest.String())}
	}

	var verificationSucceeded bool
	var verificationOutcomes []*VerificationOutcome
	var verificationFailedErrorArray = []error{ErrorVerificationFailed{}}
	errExceededMaxVerificationLimit := ErrorVerificationFailed{Msg: fmt.Sprintf("signature evaluation stopped. The configured limit of %d signatures to verify per artifact exceeded", verifyOpts.MaxSignatureAttempts)}
	numOfSignatureProcessed := 0

	// get signature manifests
	logger.Debug("Fetching signature manifests")
	err = repo.ListSignatures(ctx, artifactDescriptor, func(signatureManifests []ocispec.Descriptor) error {
		// process signatures
		for _, sigManifestDesc := range signatureManifests {
			if numOfSignatureProcessed >= verifyOpts.MaxSignatureAttempts {
				break
			}
			numOfSignatureProcessed++
			logger.Infof("Processing signature with manifest mediaType: %v and digest: %v", sigManifestDesc.MediaType, sigManifestDesc.Digest)
			// get signature envelope
			sigBlob, sigDesc, err := repo.FetchSignatureBlob(ctx, sigManifestDesc)
			if err != nil {
				return ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("unable to retrieve digital signature with digest %q associated with %q from the Repository, error : %v", sigManifestDesc.Digest, artifactRef, err.Error())}
			}

			// using signature media type fetched from registry
			opts.SignatureMediaType = sigDesc.MediaType

			// verify each signature
			outcome, err := verifier.Verify(ctx, artifactDescriptor, sigBlob, opts)
			if err != nil {
				logger.Warnf("Signature %v failed verification with error: %v", sigManifestDesc.Digest, err)
				if outcome == nil {
					logger.Error("Got nil outcome. Expecting non-nil outcome on verification failure")
					return err
				}
				outcome.Error = fmt.Errorf("failed to verify signature with digest %v, %w", sigManifestDesc.Digest, outcome.Error)
				verificationFailedErrorArray = append(verificationFailedErrorArray, outcome.Error)
				continue
			}
			// at this point, the signature is verified successfully
			verificationSucceeded = true
			// on success, verificationOutcomes only contains the
			// succeeded outcome
			verificationOutcomes = []*VerificationOutcome{outcome}
			logger.Debugf("Signature verification succeeded for artifact %v with signature digest %v", artifactDescriptor.Digest, sigManifestDesc.Digest)

			// early break on success
			return errDoneVerification
		}

		if numOfSignatureProcessed >= verifyOpts.MaxSignatureAttempts {
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
		return ocispec.Descriptor{}, nil, ErrorSignatureRetrievalFailed{Msg: fmt.Sprintf("no signature is associated with %q, make sure the artifact was signed successfully", artifactRef)}
	}

	// Verification Failed
	if !verificationSucceeded {
		logger.Debugf("Signature verification failed for all the signatures associated with artifact %v", artifactDescriptor.Digest)
		return ocispec.Descriptor{}, verificationOutcomes, errors.Join(verificationFailedErrorArray...)
	}

	// Verification Succeeded
	return artifactDescriptor, verificationOutcomes, nil
}

func generateAnnotations(signerInfo *signature.SignerInfo, annotations map[string]string) (map[string]string, error) {
	// sanity check
	if signerInfo == nil {
		return nil, errors.New("failed to generate annotations: signerInfo cannot be nil")
	}
	var thumbprints []string
	for _, cert := range signerInfo.CertificateChain {
		checkSum := sha256.Sum256(cert.Raw)
		thumbprints = append(thumbprints, hex.EncodeToString(checkSum[:]))
	}
	val, err := json.Marshal(thumbprints)
	if err != nil {
		return nil, err
	}
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[envelope.AnnotationX509ChainThumbprint] = string(val)
	signingTime, err := envelope.SigningTime(signerInfo)
	if err != nil {
		return nil, err
	}
	annotations[ocispec.AnnotationCreated] = signingTime.Format(time.RFC3339)
	return annotations, nil
}

func getDescriptorFunc(ctx context.Context, reader io.Reader, contentMediaType string, userMetadata map[string]string) BlobDescriptorGenerator {
	return func(hashAlgo digest.Algorithm) (ocispec.Descriptor, error) {
		digester := hashAlgo.Digester()
		bytes, err := io.Copy(digester.Hash(), reader)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		targetDesc := ocispec.Descriptor{
			MediaType: contentMediaType,
			Digest:    digester.Digest(),
			Size:      bytes,
		}
		return addUserMetadataToDescriptor(ctx, targetDesc, userMetadata)
	}
}

func validateContentType(contentMediaType string) error {
	if contentMediaType != "" {
		if _, _, err := mime.ParseMediaType(contentMediaType); err != nil {
			return fmt.Errorf("invalid content media-type '%s': %v", contentMediaType, err)
		}
	}
	return nil
}

func validateSigMediaType(sigMediaType string) error {
	if !(sigMediaType == jws.MediaTypeEnvelope || sigMediaType == cose.MediaTypeEnvelope) {
		return fmt.Errorf("invalid signature media-type '%s'", sigMediaType)
	}
	return nil
}
