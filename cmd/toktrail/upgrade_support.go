package main

// Supporting pieces for `toktrail upgrade`: the latest-release lookup, JSON
// output, and the small conversions the command needs.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"toktrail-collector/internal/distribution"
)

// releaseLatestAPIBase is the GitHub API root used to answer "what is the
// latest release?" when the user did not name a version. It is a package
// variable so tests can point it at a stub server; it is not configurable from
// the environment, so the network surface stays fixed and known.
var releaseLatestAPIBase = "https://api.github.com"

const (
	releaseRepoOwner = "lich0821"
	releaseRepoName  = "toktrail-collector"
	// maxReleaseJSONBytes bounds the metadata response.
	maxReleaseJSONBytes = 256 << 10
)

func currentOS() string   { return runtime.GOOS }
func currentArch() string { return runtime.GOARCH }

// resolveLatestReleaseTag asks GitHub which release is marked latest. The tag is
// validated as a precise release version; anything else is refused, so a moved
// or malformed "latest" can never select an unintended artifact.
func resolveLatestReleaseTag() (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", strings.TrimRight(releaseLatestAPIBase, "/"), releaseRepoOwner, releaseRepoName)
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", errors.New("could not build the release lookup request")
	}
	req.Header.Set("accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("the release lookup request failed (network or proxy problem)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the release lookup answered status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseJSONBytes))
	if err != nil {
		return "", errors.New("the release lookup response could not be read")
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errors.New("the release lookup response was not valid JSON")
	}
	tag := strings.TrimSpace(payload.TagName)
	if _, err := distribution.ParseVersion(tag); err != nil {
		return "", fmt.Errorf("the latest release tag %q is not a release version", tag)
	}
	return tag, nil
}

func writeUpgradeJSON(out io.Writer, payload map[string]any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(payload)
}

func decodeBase64String(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
