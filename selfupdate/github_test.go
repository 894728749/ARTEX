package selfupdate

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type releaseRoundTripFunc func(*http.Request) (*http.Response, error)

func (f releaseRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchLatestUsesMaintainedReleaseSource(t *testing.T) {
	client := &http.Client{Transport: releaseRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.URL.String(); got != "https://api.github.com/repos/cyy081021/ARTEX/releases/latest" {
			t.Fatalf("unexpected update origin: %s", got)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatal("missing GitHub API accept header")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v0.4.0","html_url":"https://github.com/cyy081021/ARTEX/releases/tag/v0.4.0","assets":[{"name":"artex-0.4.0-linux-amd64.zip","browser_download_url":"https://github.com/cyy081021/ARTEX/releases/download/v0.4.0/artex-0.4.0-linux-amd64.zip"},{"name":"SHA256SUMS","browser_download_url":"https://github.com/cyy081021/ARTEX/releases/download/v0.4.0/SHA256SUMS"}]}`)), Header: make(http.Header), Request: r}, nil
	})}
	rel, err := FetchLatest(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if cmp, ok := CompareVersions("0.3.15", rel.TagName); !ok || cmp >= 0 {
		t.Fatal("official release must be comparable to the previous stable version")
	}
	if _, ok := rel.FindAsset(AssetName(rel.TagName, "linux", "amd64")); !ok {
		t.Fatal("release asset name does not match the updater package convention")
	}
	if _, ok := rel.FindAsset("SHA256SUMS"); !ok {
		t.Fatal("release lacks checksum asset")
	}
}
