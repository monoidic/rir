package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type CachedProvider struct {
	DefaultProvider
}

func NewCachedProvider(name string, url string) CachedProvider {
	return CachedProvider{
		DefaultProvider: DefaultProvider{
			name: name,
			url:  url,
		},
	}
}

func (p CachedProvider) GetData() io.Reader {
	f := check1(os.OpenFile(p.filePath(), os.O_CREATE|os.O_RDWR, 0o700))
	defer f.Close()
	finfo := check1(f.Stat())

	if finfo.Size() > 0 && time.Since(finfo.ModTime()) < time.Hour*24 {
		// no refresh needed
	} else if finfo.Size() == 0 || p.isStale() {
		log.Printf("Refreshing %s data", p.Name())
		data := p.DefaultProvider.GetData()
		check1(io.Copy(f, data))
	}

	content := check1(os.ReadFile(f.Name()))
	return bytes.NewBuffer(content)
}

func (p CachedProvider) isStale() bool {
	local := p.localMd5()
	remote := p.remoteMd5()
	return local != remote
}

func GetCacheDir() string {
	return filepath.Join(os.Getenv("HOME"), ".rir")
}

func CreateCacheDir() {
	for _, provider := range AllProviders {
		path := filepath.Join(GetCacheDir(), provider.Name())
		check(os.MkdirAll(path, 0o700))
	}
}

func (p CachedProvider) filePath() string {
	return filepath.Join(GetCacheDir(), p.Name(), "latest")
}

func (p CachedProvider) localMd5() string {
	content := check1(os.ReadFile(p.filePath()))
	return fmt.Sprintf("%x", md5.Sum(content))
}

var MD5SigRegex = regexp.MustCompile(`(?i)([a-f0-9]{32})`)

func (p CachedProvider) remoteMd5() string {
	resp := check1(http.Get(p.url + ".md5"))
	defer resp.Body.Close()

	if status := resp.StatusCode; status != 200 {
		log.Printf("Cannot GET md5 for %s. Call returned %d", p.Name(), status)
		return ""
	}

	md5Response := check1(io.ReadAll(resp.Body))

	matches := MD5SigRegex.FindSubmatch(md5Response)

	if matches == nil {
		log.Printf("Cannot regexp match an md5 for %s", p.Name())
		return ""
	}

	return string(matches[1])
}
