package main

import (
	"flag"
	"fmt"
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

	query := Query{country: strings.ToUpper(country), ipstring: ipquery, hostscount: hostscount}

	if !(all || query.IsCountryQuery() || query.IsIpQuery()) {
		flag.Usage()
		return
	}

	CreateCacheDir()

	records := retrieveData()

	if all {
		printAll(records)
	} else if query.IsCountryQuery() {
		results := query.matchOnCountry(records)
		if query.hostscount {
			countV4 := big.NewInt(0)
			countV6 := big.NewInt(0)
			netHosts := big.NewInt(0)
			one := big.NewInt(1)
			two := big.NewInt(2)

			for r := range results {
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
				mask := uint(size - ones)
				if mask > 0 {
					netHosts.Lsh(one, mask)
					if size == 32 && mask < 31 { // network/broadcast only applicable to v4
						netHosts.Sub(netHosts, two)
					}

					count.Add(count, netHosts)
				}
			}
			fmt.Printf("v4: %s\nv6: %s\n", countV4, countV6)
		} else {
			for r := range results {
				fmt.Println(r)
			}
		}
	} else {
		for r := range query.matchOnIp(records) {
			fmt.Println(r)
		}
	}
}

func printAll(records chan Records) {
	var wg sync.WaitGroup
	ch := make(chan string, 10)
	wg.Add(len(AllProviders))
	go readRegionsAll(records, ch, &wg)

	go func() {
		wg.Wait()
		close(ch)
	}()

	for s := range ch {
		fmt.Println(s)
	}
}

func readRegionsAll(recordsCh chan Records, ch chan string, wg *sync.WaitGroup) {
	for region := range recordsCh {
		go readRecordsAll(region, ch, wg)
	}
}

func readRecordsAll(region Records, ch chan string, wg *sync.WaitGroup) {
	for _, iprecord := range region.Ips {
		cc := iprecord.Cc
		if cc == "" {
			continue
		}
		for _, net := range iprecord.Net() {
			ch <- fmt.Sprintf("%s\t%s", cc, net)
		}
	}
	wg.Done()
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

func (q Query) matchOnCountry(records chan Records) chan netip.Prefix {
	var wg sync.WaitGroup
	ch := make(chan netip.Prefix, 10)
	wg.Add(len(AllProviders))

	go readRegionsCountry(records, ch, q.country, &wg)

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}

func readRegionsCountry(recordsCh chan Records, ch chan netip.Prefix, country string, wg *sync.WaitGroup) {
	for region := range recordsCh {
		go readRecordsCountry(region, ch, country, wg)
	}
}

func readRecordsCountry(records Records, ch chan netip.Prefix, country string, wg *sync.WaitGroup) {
	for _, iprecord := range records.Ips {
		if iprecord.Cc == country && (iprecord.Type == IPv4 || iprecord.Type == IPv6) {
			for _, net := range iprecord.Net() {
				ch <- net
			}
		}
	}
	wg.Done()
}

func (q Query) matchOnIp(records chan Records) chan string {
	if q.ipstring == "" {
		flag.Usage()
	}

	var wg sync.WaitGroup
	ch := make(chan string, 10)
	wg.Add(len(AllProviders))

	go readRegionsIP(records, ch, q.ipstring, &wg)

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}

func readRegionsIP(recordsCh chan Records, ch chan string, ipstring string, wg *sync.WaitGroup) {
	addr, err := netip.ParseAddr(ipstring)
	if err != nil {
		panic(err)
	}

	for region := range recordsCh {
		go readRecordsIP(region, ch, addr, wg)
	}
}

func readRecordsIP(records Records, ch chan string, addr netip.Addr, wg *sync.WaitGroup) {
	for _, iprecord := range records.Ips {
		for _, ipnet := range iprecord.Net() {
			if ipnet.Contains(addr) {
				ch <- fmt.Sprintf("%s %s", iprecord.Cc, ipnet)
			}
		}
	}
	wg.Done()
}

func retrieveData() chan Records {
	var wg sync.WaitGroup
	ch := make(chan Records, 10)
	wg.Add(len(AllProviders))

	for _, provider := range AllProviders {
		go readProvider(provider, ch, &wg)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}

func readProvider(p Provider, ch chan Records, wg *sync.WaitGroup) {
	records, err := NewReader(p.GetData()).Read()
	if err != nil {
		log.Fatal(err)
	}
	ch <- records
	wg.Done()
}
