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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const saltsize = 16 // # of bytes of local salt for bin assignments

// Including a huge number of values is impractical for reasonable DNS
// queries, and is unlikely if Choir is being used as intended.
const maxValues = 255

// Format dates YYYYMMDD.
// All date objects are in UTC at time 00:00:00.
const dateForm = "20060102"

// Maximum number of reports per day.  This is used to limit cache memory
// usage.  If individual users are reporting more than 1000 unique
// domains per day, this library is probably not being used in the intended
// manner.
const maxReports = 1000

// ReportSender is a general interface for sending a Report to a metrics server.
type ReportSender interface {
	// Send is required to be safe for concurrent execution.
	Send(Report) error
}

// burstReportSender implements ReportSender.  It wraps another ReportSender,
// suppressing bursts of queries by only passing one randomly selected report
// in each `burst` and silently dropping the remainder.
type burstReportSender struct {
	burst   time.Duration
	sender  ReportSender
	mu      sync.Mutex // Protects `count` and `pending`.
	count   int64      // Number of reports in the current burst.
	pending Report     // Current selected report from (if count > 0).
}

func newBurstReportSender(sender ReportSender, burst time.Duration) ReportSender {
	if burst < 5*time.Second {
		log.Println("Warning: Burst duration is too low for most use cases")
	}
	return &burstReportSender{burst: burst, sender: sender}
}

func (l *burstReportSender) Send(r Report) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Keep track of how many reports have been received.
	l.count++
	// Maintain a uniformly random selection by replacing the pending report
	// with decreasing probability (reservoir sampling).
	i, err := rand.Int(rand.Reader, big.NewInt(l.count))
	if err != nil {
		return err
	} else if i.Int64() == 0 {
		// The probability of reaching this point is 1/count.
		l.pending = r
	}

	if l.count == 1 {
		// This is the first report in the burst.  Schedule a drain.
		time.AfterFunc(l.burst, l.drain)
	}
	return nil // Errors from downstream senders are lost
}

func (l *burstReportSender) drain() {
	l.mu.Lock()
	r := l.pending
	l.count = 0
	l.mu.Unlock()
	// Send the selected report.
	if err := l.sender.Send(r); err != nil {
		// Since drain() runs asynchronously, there is no way to return
		// errors to the caller.
		log.Println("Error encountered in burst report sender", err)
	}
}

// Encapsulates the domain and value, along with other information
// needed for correct anonymous reconstruction.
func name(report Report, suffix string) string {
	labels := make([]string, len(report.Values))
	for i, v := range report.Values {
		labels[i] = v.String()
	}
	labels = append(labels,
		report.bin,
		report.Country,
		report.Date.Format(dateForm),
		report.Domain,
		suffix)
	return strings.Join(labels, ".")
}

func formatQuery(name string) ([]byte, error) {
	if !strings.HasSuffix(name, ".") {
		// NewName requires names to be in "canonical form" with a trailing ".".
		name = name + "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}

	optHeader := dnsmessage.ResourceHeader{}
	udpLimit := 4096
	dummyRcode := dnsmessage.RCode(0)
	// Setting DNSSEC OK to true would request RRSIGs for the TXT record we are
	// querying.  Since we know that this TXT record doesn't exist, and we aren't
	// even checking the response, there's no need to request signatures for it.
	dnssecOK := false
	if err := optHeader.SetEDNS0(udpLimit, dummyRcode, dnssecOK); err != nil {
		return nil, err
	}

	// Address family 2 is IPv6.  This value should have no effect, but according to
	// RFC 7871, "at least one major authoritative server will ignore the option if
	// FAMILY is not 1 or 2, even though it is irrelevant if there are no ADDRESS bits".
	const ecsFamily = 2
	const ecsPrefixLength = 0 // ECS disabled
	var ecsPayload [4]byte
	binary.BigEndian.PutUint16(ecsPayload[0:], ecsFamily)
	binary.BigEndian.PutUint16(ecsPayload[2:], ecsPrefixLength)

	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  n,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: optHeader,
			Body: &dnsmessage.OPTResource{
				Options: []dnsmessage.Option{{
					Code: 0x8, // EDNS Client Subnet
					Data: ecsPayload[:],
				}},
			},
		}},
	}
	return msg.Pack()
}

// FormatQuery returns a fully serialized DNS query for a TXT record at a name
// that encodes `report`, as a subdomain of `suffix`.  The query includes an
// instruction to the recursive resolver not to reveal any information about
// the client's IP address to the authoritative server using the EDNS Client
// Subnet extension, as described in
// https://tools.ietf.org/html/rfc7871#section-7.1.2.
func FormatQuery(report Report, suffix string) ([]byte, error) {
	return formatQuery(name(report, suffix))
}

// Cache of domains that have already been reported today.
// The cache is flushed on the first report of each day.
type cache struct {
	date  time.Time // Today's date.
	cache map[string]observed
}

// Add this key to the cache.  Returns false if adding failed, because the
// key is already in the cache or is too old.
func (c *cache) Add(key Key) (added bool, err error) {
	if !key.Date.Equal(c.date) {
		if key.Date.Before(c.date) {
			// `key` has an old date.  Reject it.
			return false, fmt.Errorf("Old date: %v < %v", key.Date, c.date)
		}
		// Date has changed.  Flush the cache
		c.cache = make(map[string]observed)
		c.date = key.Date
	}
	if _, ok := c.cache[key.Domain]; ok {
		// Key is already in the map
		return false, nil
	}
	if len(c.cache) >= maxReports {
		// Too many reports today.  Cancel further reports to avoid unbounded
		// cache memory usage.
		return false, errors.New("Cache is full")
	}
	c.cache[key.Domain] = observed{}
	return true, nil
}

// Implements reportSender by wrapping another reportSender.  Only one report is permitted
// for each domain each day; duplicate reports are dropped.
type onceADayReportSender struct {
	sender ReportSender
	mu     sync.Mutex // Protects cache
	cache
}

func newOnceADayReportSender(sender ReportSender) ReportSender {
	return &onceADayReportSender{sender: sender}
}

func (s *onceADayReportSender) Send(report Report) error {
	s.mu.Lock()
	added, err := s.cache.Add(report.Key)
	s.mu.Unlock()
	if err != nil {
		log.Printf("Failed to add report to cache: %v", err)
		return nil
	} else if !added {
		log.Println("Dropping duplicate report")
		return nil
	}
	return s.sender.Send(report)
}

type binner interface {
	// Given a report key, compute a pseudorandom, consistent string.
	bin(Key) string
}

// hashBinner implements binner using a hash function with a secret local salt.
type hashBinner struct {
	salt [saltsize]byte
	bins int
}

func newHashBinner(file io.ReadWriter, bins int) (binner, error) {
	if bins <= 0 {
		return nil, errors.New("Users must be assigned to at least one bin")
	}
	var salt [saltsize]byte
	n, err := file.Read(salt[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	} else if n < saltsize {
		extra := make([]byte, saltsize-n)
		if _, err := rand.Read(extra); err != nil {
			return nil, err
		}
		if _, err := file.Write(extra); err != nil {
			return nil, err
		}
		copy(salt[n:], extra)
	}
	return hashBinner{salt, bins}, nil
}

// See encodeStd in encoding/base32
const base32 = "abcdefghijklmnopqrstuvwxyz234567"

// Count the number of characters required to represent val in base32.
func base32size(val uint) int {
	if val == 0 {
		// Representing "0" requires one character, not zero.
		return 1
	}
	size := 0
	for v := val; v != 0; v >>= 5 {
		size++
	}
	return size
}

// Returns a fixed-length base32 string representing the bin, given a
// slice of pseudorandom bytes.
func (b hashBinner) bin(k Key) string {
	// Compute assigned bin.  This behavior can be arbitrary, so long as it
	// is pseudorandom and depends only on the domain, country and date.
	components := [...]string{k.Domain, k.Country, k.Date.Format(dateForm)}
	h := hmac.New(sha256.New, b.salt[:])
	io.WriteString(h, strings.Join(components[:], ";"))
	code := h.Sum(nil)
	bin := binary.LittleEndian.Uint64(code) % uint64(b.bins)

	// Perform base32 encoding.  Doing this explicitly here is easier than
	// cleaning up the output of the encoding/base32 package, which requires
	// its input to be sized in whole bytes, and adds padding to both ends
	// of its output.
	maxBin := b.bins - 1
	size := base32size(uint(maxBin))
	chars := make([]byte, size)
	for i := size - 1; i >= 0; i-- { // Big-endian representation
		chars[i] = base32[bin&0x1f]
		bin >>= 5
	}
	return string(chars)
}

type reportBuilder struct {
	values  int
	country string
	binner
}

func today() time.Time {
	year, month, day := time.Now().UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// Encapsulates the domain and values, along with other information
// needed for correct anonymous reconstruction.  All inputs must be lower-case
// ASCII text, and each entry in the value must be at most 63 characters.
func (b reportBuilder) build(domain string, values []Value) (Report, error) {
	if len(values) != b.values {
		return Report{}, fmt.Errorf("Wrong number of values: %d != %d", len(values), b.values)
	}
	if _, err := dnsmessage.NewName(domain); err != nil {
		return Report{}, err
	}
	date := today()
	domain = normalizeForReport(domain)

	key := Key{
		Domain:  domain,
		Country: b.country,
		Date:    date,
	}

	bin := b.binner.bin(key)

	return Report{
		Key:    key,
		Values: values,
		bin:    bin,
	}, nil
}

func newReportBuilder(file io.ReadWriter, bins, values int, country string) (*reportBuilder, error) {
	if values < 0 || values > maxValues {
		return nil, fmt.Errorf("Unreasonable number of values: %d", values)
	}
	if len(country) != 2 {
		return nil, errors.New("Country code should be two characters")
	}
	country = strings.ToLower(country)
	binner, err := newHashBinner(file, bins)
	if err != nil {
		return nil, err
	}
	return &reportBuilder{values, country, binner}, nil
}

// Reporter wraps values into queries and sends them to a metrics server.
type Reporter interface {
	// Report the provided values for this domain.
	Report(domain string, values ...Value) error
}

// Implementation of Reporter.
// Reports are sent to the metrics server through a recursive resolver,
// preventing the metrics server from learning the client's IP address.
// Each report is randomly assigned to a "bin", enabling the metrics server
// to determine a lower bound on the number of users reporting this value.
// Each reporter has a fixed random salt that is used to tag reports, to
// ensure a user isn't double-counted, so it's important to use the same
// reporter for reports that might repeat.  Bin assignments are randomized
// every 24 hours to ensure that users can't be linked across time, even weakly.
// Bursts of reports are suppressed to avoid sending correlated reports.
type reporter struct {
	builder reportBuilder
	sender  ReportSender
}

// NewReporter returns a reporter that uses the salt in `file` (which may
// initially be empty) to assign reports with this many `values` to one
// of the specified number of `bins` for the client's `country`.  Bursts
// of reports are accumulated for the specified duration, and one report from
// each burst is passed asynchronously to `sender` as a Report ready to send.
func NewReporter(file io.ReadWriter, bins, values int, country string, burst time.Duration, sender ReportSender) (Reporter, error) {
	// Pipeline: builder -> onceADaySender -> burstSender -> sender
	builder, err := newReportBuilder(file, bins, values, country)
	if err != nil {
		return nil, err
	}
	burstSender := newBurstReportSender(sender, burst)
	onceADaySender := newOnceADayReportSender(burstSender)
	return &reporter{
		builder: *builder,
		sender:  onceADaySender,
	}, nil
}

// Report encapsulates the domain and values, along with other information
// needed for correct anonymous reconstruction, and schedules them to be
// sent to the metrics server.  All inputs must be lower-case ASCII text,
// and each value must be at most 63 characters.
func (r *reporter) Report(domain string, values ...Value) error {
	report, err := r.builder.build(domain, values)
	if err != nil {
		return err
	}
	return r.sender.Send(report)
}
