package azure

import (
	"encoding/xml"
	"io"
	"net/http"
	"sort"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
)

type listContainers struct {
	Containers []string `xml:"Containers>Container>Name"`
	NextMarker string   `xml:"NextMarker"`
}

func doXML(c *http.Client, req *http.Request, dst any) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, httpx.MaxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &httpx.StatusError{Code: resp.StatusCode, URL: req.URL.Path}
	}
	return xml.Unmarshal(b, dst)
}

func sortStrings(s []string) { sort.Strings(s) }
