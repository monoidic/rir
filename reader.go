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

func (ipr IpRecord) v4Net() []netip.Prefix {
	var out []netip.Prefix
	var currentIP [4]byte
	currentIPS := currentIP[:]
	hostsCount := uint32(ipr.Value)
	startIP := ipr.Start.As4()
	currentStart := binary.BigEndian.Uint32(startIP[:])

	for hostsCount > 0 {
		binary.BigEndian.PutUint32(currentIPS, currentStart)
		var minNet int

		logRes := int(math.Log2(float64(hostsCount)))
		maxRes := hostMaxLen(currentStart)
		if logRes < maxRes {
			minNet = logRes
		} else {
			minNet = maxRes
		}

		ip := netip.AddrFrom4(currentIP)

		out = append(out, netip.PrefixFrom(ip, 32-minNet))

		numHosts := uint32(1 << minNet)
		hostsCount -= numHosts
		currentStart += numHosts
	}

	return out
}

func (ipr IpRecord) v6Net() []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(ipr.Start, ipr.Value)}
}

func (ipr IpRecord) Net() []netip.Prefix {
	switch ipr.Type {
	case IPv4:
		return ipr.v4Net()
	case IPv6:
		return ipr.v6Net()
	default:
		log.Fatalf("no ipnet for ip of type '%s'", ipr.Type)
		return nil
	}
}

type Reader struct {
	s *bufio.Scanner
}

func NewReader(r io.Reader) Reader {
	return Reader{bufio.NewScanner(r)}
}

func (r Reader) Read() (Records, error) {
	asnRecords := []AsnRecord{}
	ipRecords := []IpRecord{}
	var asnCount, ipv4Count, ipv6Count int
	var version Version
	var p parser

	for r.s.Scan() {
		p.currentLine = r.s.Text()
		p.fields = strings.Split(p.currentLine, "|")

		if p.isIgnored() {
			continue
		}
		if p.isVersion() {
			version = p.parseVersion()
		} else if p.isSummary() {
			summary := p.parseSummary()
			switch summary.Type {
			case ASN:
				asnCount = summary.Count
			case IPv4:
				ipv4Count = summary.Count
			case IPv6:
				ipv6Count = summary.Count
			}
		} else if p.isIp() {
			ipRecords = append(ipRecords, p.parseIp())
		} else if p.isAsn() {
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
	}, nil

}

var (
	versionRegex = regexp.MustCompile(`^\d+\.*\d*`)
	ignoredRegex = regexp.MustCompile(`^#|^\s*$`)
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
	version, _ := strconv.ParseFloat(p.fields[0], 64)
	return Version{
		version, p.fields[1], p.fields[2], p.toInt(p.fields[3]),
		p.fields[4], p.fields[5], p.fields[6],
	}
}

func (p parser) parseSummary() Summary {
	return Summary{p.fields[0], p.fields[2], p.toInt(p.fields[4])}
}

func (p parser) parseIp() IpRecord {
	ip, err := netip.ParseAddr(p.fields[3])
	if err != nil {
		panic(err)
	}

	return IpRecord{p.buildRecord(), ip}
}

func (p parser) parseAsn() AsnRecord {
	return AsnRecord{p.buildRecord(), p.toInt(p.fields[3])}
}

func (p parser) buildRecord() Record {
	record := Record{
		Registry: p.fields[0],
		Cc:       p.fields[1],
		Type:     p.fields[2],
		Value:    p.toInt(p.fields[4]),
		Date:     p.fields[5],
		Status:   p.fields[6],
	}
	if p.isExtendedRecord() {
		record.OpaqueId = p.fields[7]
	}
	return record
}

func (p parser) isExtendedRecord() bool {
	return len(p.fields) > 7
}

func (p parser) toInt(s string) int {
	value, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalf("cannot convert string '%s' to int: %v", s, err)
	}
	return value
}
