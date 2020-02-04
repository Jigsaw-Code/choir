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
	"bytes"
	"fmt"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const country = "zz"
const burst = 10 * time.Second

var testValues []Value

func init() {
	latencyValue, _ := NewValue("150ms")
	configValue, _ := NewValue("hsts")
	testValues = []Value{latencyValue, configValue}
}

func TestReportBuilder(t *testing.T) {
	b, err := newReportBuilder(new(bytes.Buffer), 32, 2, country)
	if err != nil {
		t.Fatal(err)
	}
	domain := "destination.example"
	// This could be slightly flaky when run exactly at UTC midnight.
	now := time.Now().UTC()
	report, err := b.build(domain, testValues)
	if err != nil {
		t.Error(err)
	}
	if report.Domain != domain {
		t.Errorf("%s != %s", report.Domain, domain)
	}
	if report.Country != country {
		t.Errorf("%s != %s", report.Country, country)
	}
	for i, v := range report.Values {
		if testValues[i] != v {
			t.Errorf("%v != %v", testValues[i], v)
		}
	}
	year, month, day := report.Date.Date()
	if year != now.Year() {
		t.Errorf("%d != %d", year, now.Year())
	}
	if month != now.Month() {
		t.Errorf("%v != %v", month, now.Month())
	}
	if day != now.Day() {
		t.Errorf("%d != %d", day, now.Day())
	}

	// We have 32 bins, so the bin label should be one character.
	if len(report.bin) != 1 {
		t.Errorf("Unexpected bin: %s", report.bin)
	}
}

// Implements binner.
type testBinner string

func (b testBinner) bin(key Key) string {
	return string(b)
}

func TestReportBuilderExactBin(t *testing.T) {
	bin := "test bin"
	b := reportBuilder{
		values:  2,
		country: country,
		binner:  testBinner(bin),
	}
	domain := "destination.example"
	report, err := b.build(domain, testValues)
	if err != nil {
		t.Error(err)
	}
	if report.bin != bin {
		t.Errorf("Unexpected bin: %s", report.bin)
	}
}

var testDate = time.Date(1413, time.December, 11, 0, 0, 0, 0, time.UTC)

const testDateString = "14131211"

func TestName(t *testing.T) {
	country := "zz"
	suffixLabels := []string{"metrics", "example", "com"}
	suffix := strings.Join(suffixLabels, ".")
	domainLabels := []string{"destination", "example"}
	report := Report{
		Key: Key{
			Domain:  strings.Join(domainLabels, "."),
			Country: country,
			Date:    testDate,
		},
		Values: testValues,
		bin:    "q",
	}
	name := name(report, suffix)
	labels := strings.Split(name, ".")
	expected := []string{
		report.Values[0].String(),
		report.Values[1].String(),
		report.bin,
		report.Country,
		testDateString,
		domainLabels[0],
		domainLabels[1],
		suffixLabels[0],
		suffixLabels[1],
		suffixLabels[2],
	}
	if len(expected) != len(labels) {
		t.Errorf("Length mismatch: %d != %d", len(labels), len(expected))
	}
	for i, l := range expected {
		if labels[i] != l {
			t.Errorf("%s != %s", labels[i], l)
		}
	}
}

func TestParseReport(t *testing.T) {
	r := Receiver{
		Suffix: "metrics.example.com",
		Values: 2,
	}
	labels := []string{
		"150ms",
		"hsts",
		"q",
		"zz",
		"14131211",
		"destination",
		"example",
		"metrics",
		"example",
		"com",
	}
	report, err := r.ParseReport(strings.Join(labels, "."))
	if err != nil {
		t.Error(err)
	}
	if report.Values[0].String() != labels[0] ||
		report.Values[1].String() != labels[1] {
		t.Errorf("Wrong value: %v != %v", report.Values, labels[:2])
	}
	if report.bin != labels[2] {
		t.Errorf("%s != %s", report.bin, labels[2])
	}
	if report.Country != labels[3] {
		t.Errorf("%s != %s", report.Country, labels[3])
	}
	if report.Date.Format(dateForm) != labels[4] {
		t.Errorf("%s != %s", report.Date.Format(dateForm), labels[4])
	}
	domain := strings.Join(labels[5:7], ".")
	if report.Domain != domain {
		t.Errorf("%s != %s", report.Domain, domain)
	}
}

func TestMismatchSuffix(t *testing.T) {
	r := Receiver{
		Suffix: "metrics.example.com",
		Values: 2,
	}
	report, err := r.ParseReport("value1.value2.bin.domain.name.country.date.wrong.suffix")
	if err == nil {
		t.Errorf("Parsing should have failed: %v", report)
	}
}

func TestShortName(t *testing.T) {
	r := Receiver{
		Suffix: "metrics.example.com",
		Values: 3,
	}
	_, err := r.ParseReport("bin.short.name.country.date.metrics.example.com")
	if err == nil {
		t.Error("Parsing should have failed")
	}
}

func TestReportRoundtrip(t *testing.T) {
	suffix := "metrics.example.com"
	receiver := Receiver{
		Suffix: suffix,
		Values: 2,
	}
	original := Report{
		Key: Key{
			Domain:  "www.destination.example",
			Country: country,
			Date:    testDate,
		},
		Values: testValues,
		bin:    "q",
	}
	duplicate, err := receiver.ParseReport(name(original, suffix))
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Key != original.Key {
		t.Errorf("%v != %v", duplicate.Key, original.Key)
	}
	for i, v := range original.Values {
		if duplicate.Values[i] != v {
			t.Errorf("%s != %s", duplicate.Values[i], v)
		}
	}
	if duplicate.bin != original.bin {
		t.Errorf("%s != %s", duplicate.bin, original.bin)
	}
}

func TestBins(t *testing.T) {
	domain := "destination.example"
	for bins := 1; bins <= 255; bins++ {
		builder, err := newReportBuilder(new(bytes.Buffer), bins, 2, country)
		if err != nil {
			t.Fatal(err)
		}
		report, err := builder.build(domain, testValues)
		if err != nil {
			t.Error(err)
		}
		if bins <= 32 {
			if len(report.bin) != 1 {
				t.Errorf("Expected 1-char bin: %s", report.bin)
			}
		} else {
			if len(report.bin) != 2 {
				t.Errorf("Expected 2-char bin: %s", report.bin)
			}
		}
	}
}

func TestNoValues(t *testing.T) {
	suffix := "metrics.example.com"
	report := Report{
		Key: Key{
			Domain:  "destination.example",
			Country: country,
			Date:    testDate,
		},
		Values: nil, // This is the purpose of this test.
		bin:    "q",
	}
	name := name(report, suffix)
	if !strings.HasPrefix(name, "q.") {
		t.Errorf("%s doesn't start with the bin", name)
	}
}

func TestFormat(t *testing.T) {
	name := "abcd.efgh.i.jklm.nop.example"
	query, err := formatQuery(name)
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{}
	if err := msg.Unpack(query); err != nil {
		t.Fatal(err)
	}
	question := msg.Questions[0]
	expectedQuestion := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name + "."),
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}
	if question != expectedQuestion {
		t.Errorf("%v != %v", question, expectedQuestion)
	}
	if len(msg.Additionals) != 1 {
		t.Error("Expected 1 additional record for EDNS0")
	}
}

func TestFormatTooLong(t *testing.T) {
	// Name contains a 64-character label, but the limit is 63.
	name := "a.b.c.0123456789012345678901234567890123456789012345678901234567890123.example"
	if _, err := formatQuery(name); err == nil {
		t.Error("Expected an error due to disallowed label")
	}
}

func TestValueTooLong(t *testing.T) {
	// Value has length 64, but the limit is 63.
	v := "0123456789012345678901234567890123456789012345678901234567890123"
	if _, err := NewValue(v); err == nil {
		t.Error("Expected an error due to length limit")
	}
}

func TestValueUpperCase(t *testing.T) {
	if _, err := NewValue("Asdf"); err == nil {
		t.Error("Expected failure due to upper-case character")
	}
}

func TestValueUnicode(t *testing.T) {
	if _, err := NewValue("a⌘cd"); err == nil {
		t.Error("Expected failure due to non-ASCII character")
	}
}

func TestValueWithDot(t *testing.T) {
	if _, err := NewValue("asdf.1234"); err == nil {
		t.Error("Expected failure due to '.' in Value")
	}
}

func TestFilter(t *testing.T) {
	c := make(chan Report)
	f := Filter(c, 2)

	key := Key{
		Domain:  "d1.example",
		Country: "zz",
		Date:    testDate,
	}
	for i := 0; i < 10; i++ {
		vi, _ := NewValue(strconv.Itoa(i))
		c <- Report{
			Key:    key,
			Values: []Value{vi},
			bin:    "1",
		}
	}
	select {
	case <-f:
		t.Error("There should be no output from f yet")
	default:
	}
	go func() {
		v10, _ := NewValue("10")
		c <- Report{
			Key:    key,
			Values: []Value{v10},
			bin:    "2",
		}
		close(c)
	}()
	values := make([]int, 0)
	for report := range f {
		if report.Key != key {
			t.Errorf("Mismatched key: %v != %v", report.Key, key)
		}
		index, err := strconv.Atoi(report.Values[0].String())
		if err != nil {
			t.Error(err)
		}
		values = append(values, index)
	}
	sort.Ints(values)
	for i, v := range values {
		if i != v {
			t.Errorf("Problem with values: %v", values)
		}
	}
}

type channelReportSender chan Report

func (s channelReportSender) Send(r Report) error {
	s <- r
	close(s)
	return nil
}

func TestBurst(t *testing.T) {
	burst := 200 * time.Millisecond
	var c channelReportSender = make(chan Report)
	r, err := NewReporter(new(bytes.Buffer), 32, 2, country, burst, c)
	if err != nil {
		t.Fatal(err)
	}

	v0, _ := NewValue("asdf")
	for i := 0; i < 10; i++ {
		v1, _ := NewValue(strconv.Itoa(i))
		if err := r.Report(fmt.Sprintf("domain%d.example", i), v0, v1); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case q := <-c:
		t.Errorf("Channel shouldn't be ready yet, but got %v", q)
	default:
	}

	// This should run after the burst duration.
	report, ok := <-c
	if !ok {
		t.Fatal("Expected channel to get one entry before being closed")
	}
	if report.Country != country || report.Values[0] != v0 {
		t.Fatal("Wrong report", report)
	}
}

func TestCache(t *testing.T) {
	c := cache{}
	k := Key{
		Domain: "domain.example",
		Date:   testDate,
	}
	if added, _ := c.Add(k); !added {
		t.Error("First add should succeed")
	}
	if added, _ := c.Add(k); added {
		t.Error("Duplicate add should fail")
	}
	if added, _ := c.Add(k); added {
		t.Error("Subsequent adds should still fail")
	}
}

func TestCacheMaxReports(t *testing.T) {
	c := cache{}
	for i := 0; i < maxReports; i++ {
		k := Key{
			Domain: fmt.Sprintf("domain%d.example", i),
			Date:   testDate,
		}
		if added, err := c.Add(k); !added {
			t.Errorf("First add should succeed, but failed with err=%v", err)
		}
		if added, err := c.Add(k); added || err != nil {
			t.Errorf("Duplicate add should fail without an error, err=%v", err)
		}
	}
	newKey := Key{
		Domain: "newdomain.example",
		Date:   testDate,
	}
	if _, err := c.Add(newKey); err == nil {
		t.Error("After maxReports, all additions for that date should fail with an error")
	}
}

func TestCacheDateRollover(t *testing.T) {
	c := cache{}
	date1 := time.Date(2020, time.February, 02, 0, 0, 0, 0, time.UTC)
	date2 := time.Date(2020, time.February, 03, 0, 0, 0, 0, time.UTC)
	domain1 := "domain1.example"
	domain2 := "domain2.example"
	if added, _ := c.Add(Key{Domain: domain1, Date: date1}); !added {
		t.Error("First add should succeed")
	}
	if added, _ := c.Add(Key{Domain: domain2, Date: date1}); !added {
		t.Error("New domain on first date should succeed")
	}
	if added, _ := c.Add(Key{Domain: domain1, Date: date2}); !added {
		t.Error("Addition for a new date should succeed")
	}
	if added, err := c.Add(Key{Domain: domain2, Date: date1}); added || err == nil {
		t.Error("Addition for an old date should fail with an error")
	}
	if added, _ := c.Add(Key{Domain: domain2, Date: date2}); !added {
		t.Error("Re-addition for a new date should succeed")
	}
}

type funcReportSender (func(Report) error)

func (s funcReportSender) Send(r Report) error {
	return s(r)
}

func TestOnceADayReportSender(t *testing.T) {
	var r *Report
	var f funcReportSender = func(report Report) error {
		r = &report
		return nil
	}
	s := newOnceADayReportSender(f)

	v1, _ := NewValue("test1")
	r1 := Report{
		Key: Key{
			Domain:  "domain.example",
			Date:    testDate,
			Country: country,
		},
		Values: []Value{v1},
		bin:    "q",
	}
	if err := s.Send(r1); err != nil {
		t.Error(err)
	}

	if r == nil || r.Key != r1.Key || r.Values[0] != r1.Values[0] || r.bin != r1.bin {
		t.Errorf("Mismatch: %v != %v", r, r1)
	}

	// Report the same domain again with a different value.  The cache should
	// prevent it from being sent again.  If `sender` is called again, it will panic.
	v2, _ := NewValue("test2")
	r2 := r1          // Copy r1
	r2.Values[0] = v2 // Change the value
	// This call to Send should be a no-op due to the cache hit.  A cache hit is
	// not considered an error.
	r = nil
	if err := s.Send(r2); err != nil {
		t.Fatal(err)
	}
	if r != nil {
		t.Error("Send should not have forwarded the duplicate report")
	}

	// Try the same report on the next day.
	r3 := r1 // Copy r1
	r3.Date = r3.Date.Add(24 * time.Hour)
	if err := s.Send(r3); err != nil {
		t.Fatal(err)
	}
	// The report should have passed through the cache.
	if r == nil || r.Key != r3.Key || r.Values[0] != r3.Values[0] || r.bin != r3.bin {
		t.Errorf("Mismatch: %v != %v", r, r1)
	}
}

func TestCacheIntegration(t *testing.T) {
	burst := 0 * time.Millisecond
	var c channelReportSender = make(chan Report)
	r, err := NewReporter(new(bytes.Buffer), 32, 1, country, burst, c)
	if err != nil {
		t.Fatal(err)
	}

	v1, _ := NewValue("test1")
	if err := r.Report("domain.example", v1); err != nil {
		t.Fatal(err)
	}

	// This should run after the burst duration.
	_, ok := <-c
	if !ok {
		t.Fatal("Expected channel to get one entry before being closed")
	}

	// Report the same domain again with a different value.  The cache should
	// prevent it from being sent again.  If `sender` is called again, it will panic.
	v2, _ := NewValue("test2")
	if err := r.Report("domain.example", v2); err != nil {
		t.Fatal(err)
	}
}

func TestPopulateFile(t *testing.T) {
	buf := new(bytes.Buffer)
	_, err := NewReporter(buf, 32, 0, country, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := ioutil.ReadAll(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != 16 {
		t.Errorf("Wrong buffer size: %d", buf.Len())
	}
	foundNonZero := false
	for _, v := range salt {
		if v != 0 {
			foundNonZero = true
		}
	}
	if !foundNonZero {
		t.Error("Salt is all zeros")
	}
}

func TestReuseFile(t *testing.T) {
	buf1 := new(bytes.Buffer)
	b1, err := newReportBuilder(buf1, 32, 1, country)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := ioutil.ReadAll(buf1)
	if err != nil {
		t.Fatal(err)
	}
	buf2 := bytes.NewBuffer(salt)
	b2, err := newReportBuilder(buf2, 32, 1, country)
	if err != nil {
		t.Fatal(err)
	}
	if buf2.Len() > 0 {
		t.Error("Extra bytes unread in salt buffer")
	}

	// r1 and r2 should have the same hashing behavior.
	for i := 0; i < 100; i++ {
		domain := "domain.test"
		vi, _ := NewValue(strconv.Itoa(i))
		values := []Value{vi}
		report1, err := b1.build(domain, values)
		if err != nil {
			t.Error(err)
		}
		report2, err := b2.build(domain, values)
		if err != nil {
			t.Error(err)
		}
		if report1.Key != report2.Key || report1.bin != report2.bin ||
			len(report1.Values) != 1 || len(report2.Values) != 1 ||
			report1.Values[0] != report2.Values[0] {
			t.Errorf("Mismatch: %v != %v", report1, report2)
		}
	}
}

func ExampleReporter_Report() {
	// A real QuerySender should send queries over DNS.
	var c channelReportSender = make(chan Report)
	file := new(bytes.Buffer) // File should be persistent in real use
	burst := 0 * time.Second  // Burst should not be zero in real use
	reporter, _ := NewReporter(file, 32, 2, "ZZ", burst, c)
	v1, _ := NewValue("elt1")
	v2, _ := NewValue("elt2")
	reporter.Report("domain.example", v1, v2)
	report := <-c
	query, _ := FormatQuery(report, "metrics.example")
	fmt.Println(len(query))
	// Output: 91
}
