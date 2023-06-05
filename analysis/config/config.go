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

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/awslabs/argot/internal/funcutil"
	"gopkg.in/yaml.v3"
)

var (
	// The global config file
	configFile string
)

// SetGlobalConfig sets the global config filename
func SetGlobalConfig(filename string) {
	configFile = filename
}

// LoadGlobal loads the config file that has been set by SetGlobalConfig
func LoadGlobal() (*Config, error) {
	return Load(configFile)
}

// Config contains lists of sanitizers, sinks, sources, static commands to identify ...
// To add elements to a config file, add fields to this struct.
// If some field is not defined in the config file, it will be empty/zero in the struct.
// private fields are not populated from a yaml file, but computed after initialization
type Config struct {
	sourceFile string

	// nocalleereportfile is a file name in ReportsDir when ReportNoCalleeSites is true
	nocalleereportfile string

	// ReportsDir is the directory where all the reports will be stored. If the yaml config file this config struct has
	// been loaded does not specify a ReportsDir but sets any Report* option to true, then ReportsDir will be created
	// in the folder the binary is called.
	ReportsDir string

	// Sanitizers is the list of sanitizers for the taint analysis
	Sanitizers []CodeIdentifier

	// Validators is the list of validators for the dataflow analyses
	Validators []CodeIdentifier

	// Sinks is the list of sinks for the taint analysis
	Sinks []CodeIdentifier

	// Sources is the list of sources for the taint analysis
	Sources []CodeIdentifier

	// StaticCommands is the list of identifiers to be considered as command execution for the static commands analysi
	// (not used)
	StaticCommands []CodeIdentifier

	// BacktracePoints is the list of identifiers to be considered as entrypoint functions for the backwards dataflow analysis.
	BacktracePoints []CodeIdentifier

	// PkgFilter is a filter for the taint analysis to build summaries only for the function whose package match the
	// prefix
	PkgFilter string

	// DataFlowSpecs is a path to a json file that contains the data flows specs for the interfaces in the taint
	// analysis
	DataflowSpecs []string

	// Filters contains a list of filters that can be used by analyses
	Filters []CodeIdentifier

	// SkipInterprocedural can be set to true to skip the interprocedural (cross-function analysis) step
	SkipInterprocedural bool

	// CoverageFilter can be used to filter which packages will be reported in the coverage. If non-empty,
	// coverage will only for those packages that match CoverageFilter
	CoverageFilter string

	// ReportSummaries can be set to true, in which case summaries will be reported in a file names summaries-*.out in
	// the reports directory
	ReportSummaries bool

	// SummarizeOnDemand specifies whether the graph should build summaries on-demand instead of all at once
	SummarizeOnDemand bool

	// ReportPaths specifies whether the taint flows should be reported in separate files. For each taint flow, a new
	// file named taint-*.out will be generated with the trace from source to sink
	ReportPaths bool

	// ReportCoverage specifies whether coverage should be reported. If true, then a file names coverage-*.out will
	// be created in the report directory, containing the coverage data generated by the analysis
	ReportCoverage bool

	// ReportNoCalleeSites specifies whether the tool should report where it does not find any callee.
	ReportNoCalleeSites bool

	// MaxDepth sets a limit for the number of function call depth explored during the analysis
	// Default is 1000 (TODO: work towards not needing this)
	// If provided MaxDepth is <= 0, then it will be reset to default.
	MaxDepth int

	// MaxAlarms sets a limit for the number of alarms reported by an analysis.  If MaxAlarms > 0, then at most
	// MaxAlarms will be reported. Otherwise, if MaxAlarms <= 0, it is ignored.
	MaxAlarms int

	// Verbose control the verbosity of the tool
	Verbose bool

	// if the PkgFilter is specified
	pkgFilterRegex *regexp.Regexp

	// if the CoverageFilter is specified
	coverageFilterRegex *regexp.Regexp
}

// NewDefault returns an empty default config.
func NewDefault() *Config {
	return &Config{
		sourceFile:          "",
		nocalleereportfile:  "",
		ReportsDir:          "",
		Sanitizers:          nil,
		Sinks:               nil,
		Sources:             nil,
		StaticCommands:      nil,
		BacktracePoints:     nil,
		PkgFilter:           "",
		DataflowSpecs:       []string{},
		SkipInterprocedural: false,
		CoverageFilter:      "",
		ReportSummaries:     false,
		ReportPaths:         false,
		ReportCoverage:      false,
		ReportNoCalleeSites: false,
		MaxDepth:            1000,
		MaxAlarms:           0,
		Verbose:             false,
	}
}

// Load reads a configuration from a file
func Load(filename string) (*Config, error) {
	config := Config{}
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}
	err = yaml.Unmarshal(b, &config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config file: %w", err)
	}

	config.sourceFile = filename

	if config.ReportPaths || config.ReportSummaries || config.ReportCoverage || config.ReportNoCalleeSites {
		if config.ReportsDir == "" {
			tmpdir, err := os.MkdirTemp(path.Dir(filename), "*-report")
			if err != nil {
				return nil, fmt.Errorf("could not create temp dir for reports")
			}
			config.ReportsDir = tmpdir

			if config.ReportNoCalleeSites {
				reportFile, err := os.CreateTemp(config.ReportsDir, "nocalleesites-*.out")
				if err != nil {
					return nil, fmt.Errorf("could not create report file for no callee site")
				}
				config.nocalleereportfile = reportFile.Name()
				reportFile.Close() // the file will be reopened as needed
			}
		} else {
			err := os.Mkdir(config.ReportsDir, 0750)
			if err != nil {
				if !os.IsExist(err) {
					return nil, fmt.Errorf("could not create directory %s", config.ReportsDir)
				}
			}
		}
	}

	// Set the MaxDepth default if it is <= 0
	if config.MaxDepth <= 0 {
		config.MaxDepth = DefaultMaxCallDepth
	}

	if config.PkgFilter != "" {
		r, err := regexp.Compile(config.PkgFilter)
		if err == nil {
			config.pkgFilterRegex = r
		}
	}

	if config.CoverageFilter != "" {
		r, err := regexp.Compile(config.CoverageFilter)
		if err == nil {
			config.coverageFilterRegex = r
		}
	}

	funcutil.Iter(config.BacktracePoints, compileRegexes)
	funcutil.Iter(config.Filters, compileRegexes)
	funcutil.Iter(config.Sanitizers, compileRegexes)
	funcutil.Iter(config.Sinks, compileRegexes)
	funcutil.Iter(config.Sources, compileRegexes)
	funcutil.Iter(config.StaticCommands, compileRegexes)
	funcutil.Iter(config.Validators, compileRegexes)
	funcutil.Iter(config.Validators, compileRegexes)

	return &config, nil
}

// ReportNoCalleeFile return the file name that will contain the list of locations that have no callee
func (c Config) ReportNoCalleeFile() string {
	return c.nocalleereportfile
}

// RelPath returns filename path relative to the config source file
func (c Config) RelPath(filename string) string {
	return path.Join(path.Dir(c.sourceFile), filename)
}

// MatchPkgFilter returns true if the package name pkgname matches the package filter set in the config file. If no
// package filter has been set in the config file, the regex will match anything and return true. This function safely
// considers the case where a filter has been specified by the user but it could not be compiled to a regex. The safe
// case is to check whether the pacakge filter string is a prefix of the pkgname
func (c Config) MatchPkgFilter(pkgname string) bool {
	if c.pkgFilterRegex != nil {
		return c.pkgFilterRegex.MatchString(pkgname)
	} else if c.PkgFilter != "" {
		return strings.HasPrefix(pkgname, c.PkgFilter)
	} else {
		return false
	}
}

// MatchCoverageFilter returns true if the file name matches the coverageFilterRegex, if specified
func (c Config) MatchCoverageFilter(filename string) bool {
	if c.coverageFilterRegex != nil {
		return c.coverageFilterRegex.MatchString(filename)
	} else if c.CoverageFilter != "" {
		return strings.HasPrefix(filename, c.CoverageFilter)
	} else {
		return false
	}
}

// Below are functions used to query the configuration on specific facts

// IsSource returns true if the code identifier matches a source specification in the config file
func (c Config) IsSource(cid CodeIdentifier) bool {
	b := ExistsCid(c.Sources, cid.equalOnNonEmptyFields)
	return b
}

// IsSink returns true if the code identifier matches a sink specification in the config file
func (c Config) IsSink(cid CodeIdentifier) bool {
	return ExistsCid(c.Sinks, cid.equalOnNonEmptyFields)
}

// IsSanitizer returns true if the code identifier matches a sanitizer specification in the config file
func (c Config) IsSanitizer(cid CodeIdentifier) bool {
	return ExistsCid(c.Sanitizers, cid.equalOnNonEmptyFields)
}

// IsValidator returns true if the code identifier matches a validator specification in the config file
func (c Config) IsValidator(cid CodeIdentifier) bool {
	return ExistsCid(c.Validators, cid.equalOnNonEmptyFields)
}

// IsStaticCommand returns true if the code identifier matches a static command specification in the config file
func (c Config) IsStaticCommand(cid CodeIdentifier) bool {
	return ExistsCid(c.StaticCommands, cid.equalOnNonEmptyFields)
}

func (c Config) IsBacktracePoint(cid CodeIdentifier) bool {
	return ExistsCid(c.BacktracePoints, cid.equalOnNonEmptyFields)
}
