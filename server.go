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
	"errors"
	"strings"
	"time"
)

// Receiver represents the configuration of a metrics server, required
// to receive `Report`s in query form.
type Receiver struct {
	// The name of the metrics server, e.g. "metrics.example.com"
	Suffix string
	// The number of values in each Report.
	Values int
}

// ParseReport inverts Reporter.name(report)
func (r *Receiver) ParseReport(name string) (*Report, error) {
	for _, runeValue := range name {
		if runeValue >= 128 {
			return nil, errors.New("Non-ASCII characters are unsupported")
		}
	}
	name = normalizeForReport(name)
	suffix := normalizeForReport(r.Suffix)
	if !strings.HasSuffix(name, suffix) {
		return nil, errors.New("name is missing suffix")
	}
	name = strings.TrimSuffix(name, suffix)
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	if len(labels) <= r.Values+3 {
		return nil, errors.New("Name is too short")
	}
	valueLabels, labels := labels[:r.Values], labels[r.Values:]
	values := make([]Value, r.Values)
	for i, v := range valueLabels {
		var err error
		if values[i], err = NewValue(v); err != nil {
			return nil, err
		}
	}
	bin, labels := labels[0], labels[1:]
	country, labels := labels[0], labels[1:]
	dateLabel, labels := labels[0], labels[1:]
	domain := strings.Join(labels, ".")

	date, err := time.Parse(dateForm, dateLabel)
	if err != nil {
		return nil, err
	}

	return &Report{
		Key: Key{
			Domain:  domain,
			Country: country,
			Date:    date,
		},
		Values: values,
		bin:    bin,
	}, nil
}

// Each key has an associated dam, which holds Reports until it
// reaches a threshold number of bins and "bursts", releasing
// the Reports and any future reports as well.
type dam struct {
	// A set (map with empty values) of observed bins
	bins map[string]observed
	// All observed values.  len(observations) >= len(bins).
	observations [][]Value
}

// Add a Report to the dam.  If the number of bins exceeds the
// `threshold`, the dam bursts, releasing all the stored reports.
// If the dam has already burst, the report will be returned
// immediately.
// If `d` is `nil`, it is treated as burst.
func (d *dam) add(report Report, threshold int) []Report {
	if d == nil {
		return []Report{report}
	}
	if report.bin == "" {
		panic("Report is missing bin")
		// This could happen if the user passes the output of Filter
		// (which are reports without a bin) back into Filter again.
	}
	// Add reports behind the dam
	d.bins[report.bin] = observed{}
	d.observations = append(d.observations, report.Values)
	if len(d.bins) >= threshold {
		// The dam bursts.
		out := make([]Report, len(d.observations))
		for i, v := range d.observations {
			out[i] = Report{
				Key:    report.Key,
				Values: v,
			}
		}
		d.observations = nil
		return out
	}
	return nil
}

// Filter accepts a channel of reports (e.g. all the reports arriving at
// the metrics server) and delivers them to the output channel only if
// enough arrive to provide k-anonymity at the desired threshold.
// Callers should close the input channel when finished, to allow
// garbage-collection of any pending reports.
func Filter(in <-chan Report, threshold int) <-chan Report {
	out := make(chan Report)
	go func() {
		pending := make(map[Key]*dam)
		for report := range in {
			d, ok := pending[report.Key]
			if !ok {
				d = &dam{bins: make(map[string]observed)}
				pending[report.Key] = d
			}
			released := d.add(report, threshold)
			if released != nil {
				// The dam has burst.
				if d != nil {
					// Replace the dam with nil (which acts as
					// a burst dam) as a memory optimization.
					pending[report.Key] = nil
				}
				for _, r := range released {
					out <- r
				}
			}
		}
		close(out)
	}()
	return out
}
