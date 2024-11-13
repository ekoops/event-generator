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

package tester

import (
	"context"

	"github.com/google/uuid"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// Tester allows to verify that the running tests produce the expected outcomes.
type Tester interface {
	// StartAlertsCollection starts the process of alerts collection.
	StartAlertsCollection(ctx context.Context) error
	// Report returns a report containing information regarding the alerts matching or not matching the provided
	// expected outcome for the provided rule.
	Report(uid *uuid.UUID, rule string, expectedOutcome *loader.TestExpectedOutcome) *Report
}

// A Report contains information regarding the successful matches and generated warning for given test testing a given
// rule.
type Report struct {
	TestName          string
	RuleName          string
	SuccessfulMatches int
	GeneratedWarnings []ReportWarning
}

// Empty reports if the report specifies no successful matches and no generated warning.
func (r *Report) Empty() bool {
	return r.SuccessfulMatches == 0 && len(r.GeneratedWarnings) == 0
}

// A ReportWarning is associated to a received alert matching a rule, but having some fields not matching the expected
// outcome definition.
type ReportWarning struct {
	FieldWarnings []ReportFieldWarning
}

// ReportFieldWarning contains information regarding an expected outcome field, its expected value and the value
// contained in the alert.
type ReportFieldWarning struct {
	Field    string
	Expected any
	Got      any
}

// ReportEncoder allows to encode a report.
type ReportEncoder interface {
	// Encode encodes the provided report with a specific format and write it to the underlying destination.
	Encode(report *Report) error
}