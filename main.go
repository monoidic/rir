package main

import (
	"flag"
	"fmt"
	"iter"
	"log"
	"math/big"
	"net/netip"
	"strings"
	"sync"
)

func main() {
	var (
		all        bool
		country    string
		ipquery    string
		hostscount bool
	)

	flag.BoolVar(&all, "a", false, "print all subnets and countries in TSV")
	flag.StringVar(&country, "c", "", "2 letters string of the country (ISO 3166)")
	flag.StringVar(&ipquery, "q", "", "ip address to which to resolve country")
	flag.BoolVar(&hostscount, "n", false, "given country return possible hosts count (exclude network and broadcast addresses)")

	flag.Parse()

	query := Query{
		country:    strings.ToUpper(country),
		ipstring:   ipquery,
		hostscount: hostscount,
	}

	if !(all || query.IsCountryQuery() || query.IsIpQuery()) {
		flag.Usage()
		return
	}

	CreateCacheDir()

	switch {
	case all:
		for r := range getAll {
			fmt.Println(r)
		}

	case query.IsCountryQuery():
		if query.hostscount {
			fmt.Println(query.countryStats())
			break
		}
		for r := range query.readRegionsCountry {
			fmt.Println(r)
		}

	case query.IsIpQuery():
		for r := range query.matchOnIp {
			fmt.Println(r)
		}
	}
}

func getAll(yield func(string) bool) {
	for region := range retrieveData {
		for _, iprecord := range region.Ips {
			cc := iprecord.Cc
			if cc == "" {
				continue
			}
			for net := range bufferedSeq(iprecord.Net(), 10) {
				if !yield(fmt.Sprintf("%s\t%s", cc, net)) {
					return
				}
			}
		}
	}
}

type Query struct {
	country    string
	ipstring   string
	hostscount bool
}

func (q Query) IsCountryQuery() bool {
	return q.country != ""
}

func (q Query) IsIpQuery() bool {
	return q.ipstring != ""
}

func (q Query) readRegionsCountry(yield func(netip.Prefix) bool) {
	for region := range retrieveData {
		for _, iprecord := range region.Ips {
			if iprecord.Cc == q.country && (iprecord.Type == IPv4 || iprecord.Type == IPv6) {
				for net := range bufferedSeq(iprecord.Net(), 10) {
					if !yield(net) {
						return
					}
				}
			}
		}
	}
}

func (q Query) matchOnIp(yield func(string) bool) {
	addr := netip.MustParseAddr(q.ipstring)
	for region := range retrieveData {
		for _, iprecord := range region.Ips {
			for ipnet := range bufferedSeq(iprecord.Net(), 10) {
				if ipnet.Contains(addr) {
					if !yield(fmt.Sprintf("%s\t%s", iprecord.Cc, ipnet)) {
						return
					}
				}
			}
		}
	}
}

func (q Query) countryStats() string {
	countV4 := big.NewInt(0)
	countV6 := big.NewInt(0)
	netHosts := big.NewInt(0)
	one := big.NewInt(1)

	for r := range bufferedSeq(q.readRegionsCountry, 10) {
		ones := r.Bits()
		addr := r.Addr()
		var count *big.Int
		var size int

		if addr.Is4() {
			count = countV4
			size = 32
		} else {
			count = countV6
			size = 128
		}

		if mask := uint(size - ones); mask > 0 {
			count.Add(count, netHosts.Lsh(one, mask))
		}
	}

	return fmt.Sprintf("v4: %s\nv6: %s", countV4, countV6)
}

func retrieveData(yield func(Records) bool) {
	ch := make(chan Records, len(AllProviders))
	var wg sync.WaitGroup

	wg.Add(len(AllProviders))
	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, provider := range AllProviders {
		go func() {
			ch <- NewReader(provider.GetData()).Read()
			wg.Done()
		}()
	}

	for record := range ch {
		if !yield(record) {
			break
		}
	}
	// still drain channel on early `break`
	for range ch {
	}
}

func check(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}

func bufferedSeq[T any](seq iter.Seq[T], bufsize int) iter.Seq[T] {
	ch := make(chan T, bufsize)
	var done bool

	go func() {
		for e := range seq {
			if done {
				break
			}
			ch <- e
		}
		close(ch)
	}()

	return func(yield func(T) bool) {
		for e := range ch {
			if !yield(e) {
				break
			}
		}
		done = true
	}
}
