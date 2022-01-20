package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
)

func main() {
	country := flag.String("c", "", "2 letters string of the country (ISO 3166)")
	ipquery := flag.String("q", "", "ip address to which to resolve country")
	hostscount := flag.Bool("n", false, "given country return possible hosts count (exclude network and broadcast addresses)")

	flag.Parse()

	query := Query{country: strings.ToUpper(*country), ipstring: *ipquery, hostscount: *hostscount}

	if !(query.IsCountryQuery() || query.IsIpQuery()) {
		flag.Usage()
		return
	}

	CreateCacheDir()

	records := retrieveData()

	if query.IsCountryQuery() {
		results := query.matchOnCountry(records)
		if query.hostscount {
			count := big.NewInt(0)
			netHosts := big.NewInt(0)
			one := big.NewInt(1)
			two := big.NewInt(2)

			for r := range results {
				ones, size := r.Mask.Size()
				mask := uint(size - ones)
				if mask > 0 {
					netHosts.Lsh(one, mask)
					if size == 32 { // network/broadcast only applicable to v4
						netHosts.Sub(netHosts, two)
					}

					count.Add(count, netHosts)
				}
			}
			fmt.Println(count.String())
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

type Query struct {
	country    string
	ipstring   string
	hostscount bool
}

func (q *Query) IsCountryQuery() bool {
	return q.country != ""
}

func (q *Query) IsIpQuery() bool {
	return q.ipstring != ""
}

func (q *Query) matchOnCountry(records chan *Records) chan *net.IPNet {
	var wg sync.WaitGroup
	ch := make(chan *net.IPNet, 10)
	wg.Add(len(AllProviders))

	go func() {
		for region := range records {
			go func(records *Records) {
				for _, iprecord := range region.Ips {
					if iprecord.Cc == q.country && (iprecord.Type == IPv4 || iprecord.Type == IPv6) {
						nets := iprecord.Net()
						for _, net := range nets {
							ch <- net
						}
					}
				}
				wg.Done()
			}(region)
		}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}

func (q *Query) matchOnIp(records chan *Records) chan string {
	if q.ipstring == "" {
		flag.Usage()
	}

	var wg sync.WaitGroup
	ch := make(chan string, 10)
	wg.Add(len(AllProviders))

	go func() {
		for region := range records {
			go func(records *Records) {
				for _, iprecord := range region.Ips {
					for _, ipnet := range iprecord.Net() {
						if ipnet.Contains(net.ParseIP(q.ipstring)) {
							ch <- fmt.Sprintf("%s %s", iprecord.Cc, ipnet)
						}
					}
				}
				wg.Done()
			}(region)
		}
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}

func retrieveData() chan *Records {
	var wg sync.WaitGroup
	ch := make(chan *Records, 10)
	wg.Add(len(AllProviders))

	for _, provider := range AllProviders {
		go func(p Provider) {
			records, err := NewReader(p.GetData()).Read()
			if err != nil {
				log.Fatal(err)
			}
			ch <- records
			wg.Done()
		}(provider)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}
