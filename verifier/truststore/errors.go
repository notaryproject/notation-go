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
	WrappedError error
}

func (e ErrorTrustStore) Error() string {
	if e.WrappedError != nil {
		return e.WrappedError.Error()
	}
	return "unable to access the trust store"
}

// ErrorCertificate is used when reading a certificate failed
type ErrorCertificate struct {
	WrappedError error
}

func (e ErrorCertificate) Error() string {
	if e.WrappedError != nil {
		return e.WrappedError.Error()
	}
	return "unable to read the certificate"
}

// ErrorNonExistence is used when specified trust store or
// certificate path does not exist.
type ErrorNonExistence struct {
	WrappedError error
}

func (e ErrorNonExistence) Error() string {
	if e.WrappedError != nil {
		return e.WrappedError.Error()
	}
	return "unable to find specified trust store or certificate"
}
