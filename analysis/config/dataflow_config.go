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

package config

import "regexp"

// DataflowProblems defines all the dataflow (taint, slicing) problems in a config file.
type DataflowProblems struct {
	// PathSensitive is a boolean indicating whether the analysis should be run with access path sensitivity on
	// (will change to include more filtering in the future)
	//
	// Note that the configuration option name is "field-sensitive" because this is the name that will be more
	// recognizable for users.
	//
	// TODO deprecate since this case is covered by `"field-sensitive-funcs": [".*"]`?
	PathSensitive bool `xml:"field-sensitive" yaml:"field-sensitive" json:"field-sensitive"`

	// PathSensitiveFuncs is a list of regexes indicating which functions should be path-sensitive.
	// This allows the analysis to scale yet still maintain a degree of precision where it matters.
	PathSensitiveFuncs []string `xml:"field-sensitive-funcs" yaml:"field-sensitive-funcs" json:"field-sensitive-funcs"`

	// pathSensitiveFuncsRegexes is a list of compiled regexes corresponding to PathSensitiveFuncs
	pathSensitiveFuncsRegexes []*regexp.Regexp

	// SummarizeOnDemand specifies whether the graph should build summaries on-demand instead of all at once
	SummarizeOnDemand bool `xml:"summarize-on-demand,attr" yaml:"summarize-on-demand" json:"summarize-on-demand"`

	// UserSpecs is a path to a json file that contains the data flows specs for the interfaces in the dataflow
	// analyses
	UserSpecs []string `yaml:"user-specs" json:"user-specs"`

	// TaintTrackingProblems lists the taint tracking specifications
	TaintTrackingProblems []TaintSpec `yaml:"taint-tracking" json:"taint-tracking"`

	// SlicingProblems lists the program slicing specifications
	SlicingProblems []SlicingSpec `yaml:"slicing" json:"slicing"`
}

// TaintSpec contains code identifiers that identify a specific taint tracking problem, or contains a code that
// can differentiate groups of annotations
type TaintSpec struct {
	*AnalysisProblemOptions `xml:"analysis-options,attr" yaml:"analysis-options" json:"analysis-options"`
	// Sanitizers is the list of sanitizers for the taint analysis
	Sanitizers []CodeIdentifier

	// Validators is the list of validators for the dataflow analyses
	Validators []CodeIdentifier

	// Sinks is the list of sinks for the taint analysis
	Sinks []CodeIdentifier

	// Sources is the list of sources for the taint analysis
	Sources []CodeIdentifier

	// Filters contains a list of filters that can be used by analyses
	Filters []CodeIdentifier

	// Tag identifies a group of annotations when used with annotations
	Tag string

	// Severity assigns a severity to this problem
	Severity string

	// Description allows the user to add a description to the problem
	Description string

	// FailOnImplicitFlow indicates whether the taint analysis should fail when tainted data implicitly changes
	// the control flow of a program. This should be set to false when proving a data flow property,
	// and set to true when proving an information flow property.
	FailOnImplicitFlow bool `yaml:"fail-on-implicit-flow" json:"fail-on-implicit-flow"`

	// SkipBoundLabels indicates whether to skip flows that go through "bound labels", i.e. aliases of the variables
	// bound by a closure. This can be useful to test data flows because bound labels generate a lot of false positives.
	SkipBoundLabels bool `yaml:"unsafe-skip-bound-labels" json:"unsafe-skip-bound-labels"`
}

// SlicingSpec contains code identifiers that identify a specific program slicing / backwards dataflow analysis spec.
type SlicingSpec struct {
	*AnalysisProblemOptions `xml:"analysis-options,attr" yaml:"analysis-options" json:"analysis-options"`
	// BacktracePoints is the list of identifiers to be considered as entrypoint functions for the backwards
	// dataflow analysis.
	BacktracePoints []CodeIdentifier

	// Filters contains a list of filters that can be used by analyses
	Filters []CodeIdentifier

	// Tag identifies a group of annotations when used with annotations
	Tag string

	// Severity assigns a severity to this problem
	Severity string

	// Description allows the user to add a description to the problem
	Description string

	// SkipBoundLabels indicates whether to skip flows that go through "bound labels", i.e. aliases of the variables
	// bound by a closure. This can be useful to test data flows because bound labels generate a lot of false positives.
	SkipBoundLabels bool `yaml:"unsafe-skip-bound-labels" json:"unsafe-skip-bound-labels"`
}

// IsPathSensitiveFunc returns true if funcName matches any regex in c.Options.PathSensitiveFuncs.
func (c Config) IsPathSensitiveFunc(funcName string) bool {
	for _, psfr := range c.pathSensitiveFuncsRegexes {
		if psfr == nil {
			continue
		}
		if psfr.MatchString(funcName) {
			return true
		}
	}

	return false
}

// Below are functions used to query the configuration on specific facts

func (c Config) isSomeTaintSpecCid(cid CodeIdentifier, f func(t TaintSpec, cid CodeIdentifier) bool) bool {
	for _, x := range c.DataflowProblems.TaintTrackingProblems {
		if f(x, cid) {
			return true
		}
	}
	return false
}

// IsSomeSource returns true if the code identifier matches any source in the config
func (c Config) IsSomeSource(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsSource(cid2) })
}

// IsSomeSink returns true if the code identifier matches any sink in the config
func (c Config) IsSomeSink(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsSink(cid2) })
}

// IsSomeSanitizer returns true if the code identifier matches any sanitizer in the config
func (c Config) IsSomeSanitizer(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsSanitizer(cid2) })
}

// IsSomeValidator returns true if the code identifier matches any validator in the config
func (c Config) IsSomeValidator(cid CodeIdentifier) bool {
	return c.isSomeTaintSpecCid(cid, func(t TaintSpec, cid2 CodeIdentifier) bool { return t.IsValidator(cid2) })
}

// IsSomeBacktracePoint returns true if the code identifier matches any backtrace point in the slicing problems
func (c Config) IsSomeBacktracePoint(cid CodeIdentifier) bool {
	for _, ss := range c.DataflowProblems.SlicingProblems {
		if ss.IsBacktracePoint(cid) {
			return true
		}
	}
	return false
}

// IsSource returns true if the code identifier matches a source specification in the config file
func (ts TaintSpec) IsSource(cid CodeIdentifier) bool {
	b := ExistsCid(ts.Sources, cid.equalOnNonEmptyFields)
	return b
}

// IsSink returns true if the code identifier matches a sink specification in the config file
func (ts TaintSpec) IsSink(cid CodeIdentifier) bool {
	return ExistsCid(ts.Sinks, cid.equalOnNonEmptyFields)
}

// IsSanitizer returns true if the code identifier matches a sanitizer specification in the config file
func (ts TaintSpec) IsSanitizer(cid CodeIdentifier) bool {
	return ExistsCid(ts.Sanitizers, cid.equalOnNonEmptyFields)
}

// IsValidator returns true if the code identifier matches a validator specification in the config file
func (ts TaintSpec) IsValidator(cid CodeIdentifier) bool {
	return ExistsCid(ts.Validators, cid.equalOnNonEmptyFields)
}

// IsStaticCommand returns true if the code identifier matches a static command specification in the config file
func (scs StaticCommandsSpec) IsStaticCommand(cid CodeIdentifier) bool {
	return ExistsCid(scs.StaticCommands, cid.equalOnNonEmptyFields)
}

// IsBacktracePoint returns true if the code identifier matches a backtrace point according to the SlicingSpec
func (ss SlicingSpec) IsBacktracePoint(cid CodeIdentifier) bool {
	return ExistsCid(ss.BacktracePoints, cid.equalOnNonEmptyFields)
}
