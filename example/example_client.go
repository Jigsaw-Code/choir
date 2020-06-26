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

// This sample demonstrates use of Choir in a client application.
// It presents a simple example of a client application that processes
// user-selected domains, and reports errors using Choir's privacy-
// preserving reporting system.
//
// To get started, type "go run ." in the example directory.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Jigsaw-Code/choir"
	"golang.org/x/net/dns/dnsmessage"
)

// Extract the IP (and port) of the user's current default resolver.
func getRecursiveAddress() string {
	var serverAddress string
	// This fake Dial function serves to capture the address argument, which is
	// the IP address of the recursive resolver.  Go has built-in functionality
	// to determine the recursive resolver IP address from platform-specific
	// configuration, but does not otherwise expose this information.
	fakeDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		serverAddress = address
		return nil, errors.New("Fake dialer")
	}

	(&net.Resolver{
		PreferGo: true,
		Dial:     fakeDial,
	}).LookupTXT(context.Background(), "noname.example")

	return serverAddress
}

// This is the domain where the customized authoritative DNS server is logging
// incoming reports.
const metricsDomain = "metrics.example"

// This example ReportSender encodes the report as a DNS query and sends it over UDP.
// An encrypted transport is recommended if available.
type udpDNSReportSender struct {
	serverAddress string
}

func (s udpDNSReportSender) Send(r choir.Report) error {
	query, err := choir.FormatQuery(r, metricsDomain)
	if err != nil {
		return err
	}
	msg := &dnsmessage.Message{}
	if err := msg.Unpack(query); err != nil {
		log.Fatal(err)
	}
	name := msg.Questions[0].Name.String()
	log.Printf("Querying %s via %s\n", name, s.serverAddress)
	c, err := net.Dial("udp", s.serverAddress)
	if err != nil {
		log.Fatal("Failed to reach resolver:", err)
	}
	if _, err := c.Write(query); err != nil {
		log.Printf("Warning: Query failed: %v", err)
	} else {
		var buf [4096]byte
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf[:])
		if err != nil {
			log.Printf("Reading response failed: %v", err)
		} else {
			var msg dnsmessage.Message
			if err := msg.Unpack(buf[:n]); err != nil {
				log.Printf("Bad response: %v", err)
			} else if msg.Header.RCode != dnsmessage.RCodeNameError {
				// We expect an NXDOMAIN response.  Anything else is surprising.
				log.Printf("Unexpected response: %v", msg.Header.RCode)
			} else {
				log.Printf("Report complete")
			}
		}
	}
	c.Close()
	return nil
}

// Get the user's current country from an IP geolocation service.
func getClientCountry() string {
	resp, err := http.Get("https://ipinfo.io/country")
	if err != nil {
		log.Fatal("Failed to get client country:", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("Failed to get client country:", resp.StatusCode)
	}
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response body")
	}
	resp.Body.Close()
	clientCountry := string(contents[:2])
	return clientCountry
}

func mustMakeReporter() choir.Reporter {
	// This filename is consistent across invocations, ensuring that
	// the bin assignments are stable over the course of a day.
	filename := filepath.Join(os.TempDir(), "choir_example_salt")
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	const bins = 32
	clientCountry := getClientCountry()
	const burst = 10 * time.Second
	sender := udpDNSReportSender{getRecursiveAddress()}
	reporter, err := choir.NewReporter(file, bins, 2, clientCountry, burst, sender)
	if err != nil {
		log.Fatal(err)
	}
	return reporter
}

// `reporter` should be a long-lived object, used for multiple queries.
var reporter = mustMakeReporter()

func checkURL(rawurl string) error {
	resp, err := http.Get(rawurl)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Queueing report for %s with status %d\n", rawurl, resp.StatusCode)
		u, err := url.ParseRequestURI(rawurl)
		if err != nil {
			return err
		}

		// Round 40X to 400, 50X to 500.
		responseClass := 100 * (resp.StatusCode / 100)
		scheme, err := choir.NewValue(u.Scheme)
		if err != nil {
			return err
		}
		class, err := choir.NewValue(strconv.Itoa(responseClass))
		if err != nil {
			return err
		}
		if err := reporter.Report(u.Hostname(), scheme, class); err != nil {
			return err
		}
	}
	return nil
}

// Minimal network utility that processes user-provided URLs.
func main() {
	fmt.Println("Enter URLs separate by spaces, and press enter to load them. " +
		"Each URL will be loaded, and responses that indicate an HTTP error " +
		"(e.g. https://yahoo.com/asdf -> 404) will be reported via Choir after " +
		" a 10 second delay.  Ctrl-C to exit.")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("URLs: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		rawurls := strings.Split(strings.TrimSpace(input), " ")
		for _, rawurl := range rawurls {
			if len(rawurl) == 0 {
				continue
			}
			if err := checkURL(rawurl); err != nil {
				log.Printf("Loading %s failed: %v\n", rawurl, err)
			}
		}
		log.Println("Done")
	}
}
