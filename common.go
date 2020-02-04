// Copyright 2020 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package choir

import (
	"fmt"
	"strings"
	"time"
)

// Key is the Quasi-Identifying information associated with a report.
// It is protected by k-anonymity when using bin count filtering.
type Key struct {
	Domain  string
	Country string
	Date    time.Time
}

// Value represents a string that has been validated as correctly formatted for
// inclusion in a Report.  A correctly formatted Value is a string of length 63
// or less that does not contain a '.', upper-case characters, or any characters
// beyond basic ASCII.  These restrictions ensure that a Value can be passed
// through the DNS as a label without data loss.
type Value struct {
	v string
}

func (v Value) String() string {
	return v.v
}

// NewValue converts `v` to a Value, or returns an error if `v` is not a valid value.
func NewValue(v string) (Value, error) {
	if strings.ContainsRune(v, '.') {
		return Value{}, fmt.Errorf("Values cannot contain '.': %s", v)
	}
	if strings.ToLower(v) != v {
		return Value{}, fmt.Errorf("Values must be all lower-case: %s", v)
	}
	if len(v) > 63 {
		return Value{}, fmt.Errorf("Value is longer than 63 bytes: %s", v)
	}
	for _, runeValue := range v {
		if runeValue >= 128 {
			return Value{}, fmt.Errorf("Values must contain only ASCII basic characters: %s", v)
		}
	}
	return Value{v}, nil
}

// Report represents a full report to the server.
type Report struct {
	Key
	// Each report contains a zero or more values.
	// These values should not contain any potentially identifying information,
	// because they are revealed to the recursive resolver and are not protected
	// by k-anonymity.  A single user can make multiple reports with the same
	// or different values, but only one report will be sent for each Key.
	Values []Value
	bin    string
}

// Used in the implementation of sets as map[...]observed.
type observed struct{}

// Domains are always handled in lower case, without the trailing ".".
func normalizeForReport(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
