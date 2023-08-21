// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package taint

import (
	"regexp"
	"testing"
)

func TestEscapeIntegration(t *testing.T) {
	// Closures not implemented
	r := regexp.MustCompile("missing escape for (.*\\$.*) in context")
	runTest(t, "escape-integration", []string{}, false,
		func(e error) bool { return r.MatchString(e.Error()) })
}

func TestPlayground(t *testing.T) {
	runTest(t, "playground", []string{}, false, noErrorExpected)
}
