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

package proto

import "github.com/notaryproject/notation-plugin-framework-go/plugin"

// GetMetadataRequest contains the parameters passed in a get-plugin-metadata request.
//
// Deprecated: GetMetadataRequest exists for historical compatibility and should not be used.
// To access GetMetadataRequest, use the notation-plugin-framework-go's [plugin.GetMetadataRequest] type.
type GetMetadataRequest = plugin.GetMetadataRequest

// GetMetadataResponse provided by the plugin.
//
// Deprecated: GetMetadataResponse exists for historical compatibility and should not be used.
// To access GetMetadataResponse, use the notation-plugin-framework-go's [plugin.GetMetadataResponse] type.
type GetMetadataResponse = plugin.GetMetadataResponse
