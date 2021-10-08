// Package pki contains certificate management protocol structures
// defined in RFC 2510.
package pki

import "encoding/asn1"

// PKIStatus is defined in RFC 2510 3.2.3.
const (
	StatusGranted                = 0 // you got exactly what you asked for
	StatusGrantedWithMods        = 1 // you got something like what you asked for
	StatusRejection              = 2 // you don't get it, more information elsewhere in the message
	StatusWaiting                = 3 // the request body part has not yet been processed, expect to hear more later
	StatusRevocationWarning      = 4 // this message contains a warning that a revocation is imminent
	StatusRevocationNotification = 5 // notification that a revocation has occurred
	StatusKeyUpdateWarning       = 6 // update already done for the oldCertId specified in the key update request message
)

// PKIFailureInfo is defined in RFC 2510 3.2.3 and RFC 3161 2.4.2.
const (
	FailureInfoBadAlg              = 0  // unrecognized or unsupported Algorithm Identifier
	FailureInfoBadMessageCheck     = 1  // integrity check failed (e.g., signature did not verify)
	FailureInfoBadRequest          = 2  // transaction not permitted or supported
	FailureInfoBadTime             = 3  // messageTime was not sufficiently close to the system time, as defined by local policy
	FailureInfoBadCertID           = 4  // no certificate could be found matching the provided criteria
	FailureInfoBadDataFormat       = 5  // the data submitted has the wrong format
	FailureInfoWrongAuthority      = 6  // the authority indicated in the request is different from the one creating the response token
	FailureInfoIncorrectData       = 7  // the requester's data is incorrect (used for notary services)
	FailureInfoMissingTimeStamp    = 8  // the timestamp is missing but should be there (by policy)
	FailureInfoBadPOP              = 9  // the proof-of-possession failed
	FailureInfoTimeNotAvailable    = 14 // the TSA's time source is not available
	FailureInfoUnacceptedPolicy    = 15 // the requested TSA policy is not supported by the TSA.
	FailureInfoUnacceptedExtension = 16 // the requested extension is not supported by the TSA.
	FailureInfoAddInfoNotAvailable = 17 // the additional information requested could not be understood or is not available
	FailureInfoSystemFailure       = 25 // the request cannot be handled due to system failure
)

// StatusInfo contains status codes and failure information for PKI messages.
// PKIStatusInfo ::= SEQUENCE {
//  status          PKIStatus,
//  statusString    PKIFreeText     OPTIONAL,
//  failInfo        PKIFailureInfo  OPTIONAL }
// PKIStatus        ::= INTEGER
// PKIFreeText      ::= SEQUENCE SIZE (1..MAX) OF UTF8String
// PKIFailureInfo   ::= BIT STRING
// Reference: RFC 2510 3.2.3 Status codes and Failure Information for PKI messages.
type StatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}
