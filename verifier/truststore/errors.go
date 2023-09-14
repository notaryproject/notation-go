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

package truststore

// ErrorTrustStore is used when accessing specified trust store failed
type ErrorTrustStore struct {
	Msg        string
	InnerError error
}

func (e ErrorTrustStore) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "unable to access the trust store"
}

func (e ErrorTrustStore) Unwrap() error {
	return e.InnerError
}

// ErrorCertificate is used when reading a certificate failed
type ErrorCertificate struct {
	Msg        string
	InnerError error
}

func (e ErrorCertificate) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.InnerError != nil {
		return e.InnerError.Error()
	}
	return "unable to read the certificate"
}

func (e ErrorCertificate) Unwrap() error {
	return e.InnerError
}