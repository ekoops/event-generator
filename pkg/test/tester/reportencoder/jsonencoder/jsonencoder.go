// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jsonencoder

import (
	"encoding/json"
	"io"

	"github.com/falcosecurity/event-generator/pkg/test/tester"
)

// jsonEncoder is an implementation of tester.ReportEncoder allowing to write a report to the underlying destination
// using a JSON encoding.
type jsonEncoder struct {
	writer io.Writer
}

// Verify that jsonEncoder implements tester.ReportEncoder interface.
var _ tester.ReportEncoder = (*jsonEncoder)(nil)

// New creates a new report JSON encoder.
func New(w io.Writer) tester.ReportEncoder {
	je := &jsonEncoder{writer: w}
	return je
}

func (je *jsonEncoder) Encode(report *tester.Report) error {
	encoder := json.NewEncoder(je.writer)
	return encoder.Encode(report)
}