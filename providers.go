package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
)

type Provider interface {
	Name() string
	GetData() io.Reader
}

type DefaultProvider struct {
	name string
	url  string
}

func (p DefaultProvider) Name() string {
	return p.name
}

func (p DefaultProvider) GetData() io.Reader {
	log.Printf("Fetching %s data", p.Name())
	response := check1(http.Get(p.url))
	defer response.Body.Close()

	if status := response.StatusCode; status != 200 {
		log.Fatalf("HTTP call returned %d", status)
	}

	content := check1(io.ReadAll(response.Body))

	return bytes.NewBuffer(content)
}

var AllProviders = []CachedProvider{
	NewCachedProvider(
		"afrinic",
		"https://ftp.ripe.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
	),
	NewCachedProvider(
		"apnic",
		"https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-extended-latest",
	),
	NewCachedProvider(
		"arin",
		"https://ftp.ripe.net/pub/stats/arin/delegated-arin-extended-latest",
	),
	NewCachedProvider(
		"lacnic",
		"https://ftp.ripe.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	),
	NewCachedProvider(
		"ripencc",
		"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	),
	//NewCachedProvider(
	//	"iana",
	//	"http://ftp.apnic.net/stats/iana/delegated-iana-latest",
	//),
}
