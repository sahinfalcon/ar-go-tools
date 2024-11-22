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

// ConfigLogger groups a config and a logger. All "state" structs should implement this.
type ConfigLogger interface {
	GetConfig() *Config
	GetLogger() *LogGroup
}

// A State for config is a config with a logger.
type State struct {
	Config *Config
	Logger *LogGroup
}

// NewState returns a new state from a config by adding a logger built from that config.
func NewState(c *Config) *State {
	return &State{
		Config: c,
		Logger: NewLogGroup(c),
	}
}

// GetConfig returns the config of the state
func (s *State) GetConfig() *Config {
	return s.Config
}

// GetLogger returns the logger of the state
func (s *State) GetLogger() *LogGroup {
	return s.Logger
}
