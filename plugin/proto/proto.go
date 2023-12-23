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

// Package proto defines the protocol layer for communication between notation
// and notation external plugin.
package proto

// Prefix is the prefix required on all plugin binary names.
const Prefix = "notation-"

// ContractVersion is the <major>.<minor> version of the plugin contract.
const ContractVersion = "1.0"
