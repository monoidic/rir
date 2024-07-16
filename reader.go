package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	IPv4 = "ipv4"
	IPv6 = "ipv6"
	ASN  = "asn"
)

type (
	Summary struct {
		Registry, Type string
		Count          int
	}

	Version struct {
		Version                       float64
		Registry, Serial              string
		Records                       int
		StartDate, EndDate, UtcOffset string
	}

	Record struct {
		Registry, Cc, Type     string
		Value                  int
		Date, Status, OpaqueId string
	}

	IpRecord struct {
		Record
		Start netip.Addr
	}

	AsnRecord struct {
		Record
		Start int
	}

	Records struct {
		Version                               float64
		Count, AsnCount, Ipv4Count, Ipv6Count int
		Asns                                  []AsnRecord
		Ips                                   []IpRecord
	}
)

func hostMaxLen(ip uint32) int {
	if ip == 0 {
		return 32
	}
	res := 0
	for ip&1 == 0 {
		ip >>= 1
		res++
	}

	return res
}

func (ipr IpRecord) v4Net(yield func(netip.Prefix) bool) {
	var currentIP [4]byte
	currentIPS := currentIP[:]
	hostsCount := uint32(ipr.Value)
	startIP := ipr.Start.As4()
	currentStart := binary.BigEndian.Uint32(startIP[:])

	for hostsCount > 0 {
		binary.BigEndian.PutUint32(currentIPS, currentStart)

		logRes := int(math.Log2(float64(hostsCount)))
		maxRes := hostMaxLen(currentStart)
		minNet := maxRes
		if logRes < maxRes {
			minNet = logRes
		}

		ip := netip.AddrFrom4(currentIP)

		if !yield(netip.PrefixFrom(ip, 32-minNet)) {
			return
		}

		numHosts := uint32(1 << minNet)
		hostsCount -= numHosts
		currentStart += numHosts
	}
}

func (ipr IpRecord) v6Net(yield func(netip.Prefix) bool) {
	yield(netip.PrefixFrom(ipr.Start, ipr.Value))
}

func (ipr IpRecord) Net(yield func(netip.Prefix) bool) {
	switch ipr.Type {
	case IPv4:
		ipr.v4Net(yield)
	case IPv6:
		ipr.v6Net(yield)
	default:
		log.Fatalf("no ipnet for ip of type '%s'", ipr.Type)
	}
}

type Reader struct {
	s *bufio.Scanner
}

func NewReader(r io.Reader) Reader {
	return Reader{
		s: bufio.NewScanner(r),
	}
}

func (r Reader) Read() Records {
	var asnRecords []AsnRecord
	var ipRecords []IpRecord
	var asnCount, ipv4Count, ipv6Count int
	var version Version
	var p parser

	for r.s.Scan() {
		p.currentLine = r.s.Text()
		p.fields = strings.Split(p.currentLine, "|")

		switch {
		case p.isIgnored():
			// ignored
		case p.isVersion():
			version = p.parseVersion()
		case p.isSummary():
			summary := p.parseSummary()
			switch summary.Type {
			case ASN:
				asnCount = summary.Count
			case IPv4:
				ipv4Count = summary.Count
			case IPv6:
				ipv6Count = summary.Count
			}
		case p.isIp():
			ipRecords = append(ipRecords, p.parseIp())
		case p.isAsn():
			asnRecords = append(asnRecords, p.parseAsn())
		}
	}

	return Records{
		Version:   version.Version,
		Count:     version.Records,
		AsnCount:  asnCount,
		Ipv4Count: ipv4Count,
		Ipv6Count: ipv6Count,
		Asns:      asnRecords,
		Ips:       ipRecords,
	}

}

var (
	versionRegex = regexp.MustCompile(`^\d+\.*\d*`)
	ignoredRegex = regexp.MustCompile(`^\s*(#.*)?$`)
)

type parser struct {
	currentLine string
	fields      []string
}

func (p parser) isVersion() bool {
	return versionRegex.MatchString(p.currentLine)
}

func (p parser) isIgnored() bool {
	return ignoredRegex.MatchString(p.currentLine)
}

func (p parser) isSummary() bool {
	return strings.HasSuffix(p.currentLine, "summary")
}

func (p parser) isIp() bool {
	return strings.HasPrefix(p.fields[2], "ipv")
}

func (p parser) isAsn() bool {
	return strings.HasPrefix(p.fields[2], ASN)
}

func (p parser) parseVersion() Version {
	return Version{
		Version:   check1(strconv.ParseFloat(p.fields[0], 64)),
		Registry:  p.fields[1],
		Serial:    p.fields[2],
		Records:   check1(strconv.Atoi(p.fields[3])),
		StartDate: p.fields[4],
		EndDate:   p.fields[5],
		UtcOffset: p.fields[6],
	}
}

func (p parser) parseSummary() Summary {
	return Summary{
		Registry: p.fields[0],
		Type:     p.fields[2],
		Count:    check1(strconv.Atoi(p.fields[4])),
	}
}

func (p parser) parseIp() IpRecord {
	return IpRecord{
		Record: p.buildRecord(),
		Start:  netip.MustParseAddr(p.fields[3]),
	}
}

func (p parser) parseAsn() AsnRecord {
	return AsnRecord{
		Record: p.buildRecord(),
		Start:  check1(strconv.Atoi(p.fields[3])),
	}
}

func (p parser) buildRecord() Record {
	record := Record{
		Registry: p.fields[0],
		Cc:       p.fields[1],
		Type:     p.fields[2],
		Value:    check1(strconv.Atoi(p.fields[4])),
		Date:     p.fields[5],
		Status:   p.fields[6],
	}

	if len(p.fields) > 7 { // extended record
		record.OpaqueId = p.fields[7]
	}

	return record
}
