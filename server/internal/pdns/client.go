// Package pdns is a client for the PowerDNS Authoritative Server HTTP API.
package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL  string
	apiKey   string
	serverID string
	http     *http.Client
}

func New(baseURL, apiKey, serverID string) *Client {
	if serverID == "" {
		serverID = "localhost"
	}
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   apiKey,
		serverID: serverID,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Error is returned for non-2xx responses from PowerDNS.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("powerdns: %s (HTTP %d)", e.Message, e.Status)
}

func IsNotFound(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Status == http.StatusNotFound
	}
	return false
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/api/v1"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		var e struct {
			Error  string   `json:"error"`
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
			if len(e.Errors) > 0 {
				msg += ": " + strings.Join(e.Errors, "; ")
			}
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return &Error{Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if s, ok := out.(*string); ok {
		*s = string(data)
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) srv() string { return "/servers/" + url.PathEscape(c.serverID) }

func zonePath(zoneID string) string { return "/zones/" + url.PathEscape(zoneID) }

// ---- Types ----

type ServerInfo struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
	URL        string `json:"url"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type Comment struct {
	Content    string `json:"content"`
	Account    string `json:"account"`
	ModifiedAt int64  `json:"modified_at"`
}

type RRSet struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	TTL        int       `json:"ttl,omitempty"`
	ChangeType string    `json:"changetype,omitempty"`
	Records    []Record  `json:"records"`
	Comments   []Comment `json:"comments"`
}

type Zone struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name"`
	Kind             string   `json:"kind,omitempty"`
	Serial           int64    `json:"serial,omitempty"`
	NotifiedSerial   int64    `json:"notified_serial,omitempty"`
	EditedSerial     int64    `json:"edited_serial,omitempty"`
	Masters          []string `json:"masters,omitempty"`
	DNSSEC           bool     `json:"dnssec"`
	NSEC3Param       string   `json:"nsec3param,omitempty"`
	NSEC3Narrow      bool     `json:"nsec3narrow,omitempty"`
	Presigned        bool     `json:"presigned,omitempty"`
	SOAEdit          string   `json:"soa_edit,omitempty"`
	SOAEditAPI       string   `json:"soa_edit_api,omitempty"`
	APIRectify       bool     `json:"api_rectify"`
	Account          string   `json:"account,omitempty"`
	Catalog          string   `json:"catalog,omitempty"`
	Nameservers      []string `json:"nameservers,omitempty"`
	MasterTSIGKeyIDs []string `json:"master_tsig_key_ids,omitempty"`
	SlaveTSIGKeyIDs  []string `json:"slave_tsig_key_ids,omitempty"`
	LastCheck        int64    `json:"last_check,omitempty"`
	RRSets           []RRSet  `json:"rrsets,omitempty"`
}

type CryptoKey struct {
	ID         int      `json:"id,omitempty"`
	KeyType    string   `json:"keytype,omitempty"`
	Active     bool     `json:"active"`
	Published  bool     `json:"published"`
	DNSKey     string   `json:"dnskey,omitempty"`
	DS         []string `json:"ds,omitempty"`
	CDS        []string `json:"cds,omitempty"`
	Algorithm  string   `json:"algorithm,omitempty"`
	Bits       int      `json:"bits,omitempty"`
	PrivateKey string   `json:"privatekey,omitempty"`
}

type Metadata struct {
	Kind     string   `json:"kind"`
	Metadata []string `json:"metadata"`
}

type TSIGKey struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Key       string `json:"key,omitempty"`
}

type Statistic struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
	Size  json.RawMessage `json:"size,omitempty"`
}

type SearchResult struct {
	Content    string `json:"content"`
	Disabled   bool   `json:"disabled"`
	Name       string `json:"name"`
	ObjectType string `json:"object_type"`
	Zone       string `json:"zone"`
	ZoneID     string `json:"zone_id"`
	Type       string `json:"type"`
	TTL        int    `json:"ttl"`
}

// ---- Server ----

func (c *Client) Server(ctx context.Context) (*ServerInfo, error) {
	var s ServerInfo
	return &s, c.do(ctx, http.MethodGet, c.srv(), nil, &s)
}

func (c *Client) Statistics(ctx context.Context) ([]Statistic, error) {
	var s []Statistic
	return s, c.do(ctx, http.MethodGet, c.srv()+"/statistics?includerings=true", nil, &s)
}

func (c *Client) Search(ctx context.Context, q string, max int) ([]SearchResult, error) {
	var r []SearchResult
	p := fmt.Sprintf("%s/search-data?q=%s&max=%d&object_type=all", c.srv(), url.QueryEscape(q), max)
	return r, c.do(ctx, http.MethodGet, p, nil, &r)
}

// ConfigSetting is one entry from the server's running configuration.
type ConfigSetting struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (c *Client) Config(ctx context.Context) ([]ConfigSetting, error) {
	var s []ConfigSetting
	return s, c.do(ctx, http.MethodGet, c.srv()+"/config", nil, &s)
}

func (c *Client) FlushCache(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodPut, c.srv()+"/cache/flush?domain="+url.QueryEscape(domain), nil, nil)
}

// ---- Zones ----

func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var z []Zone
	return z, c.do(ctx, http.MethodGet, c.srv()+"/zones?dnssec=false", nil, &z)
}

func (c *Client) GetZone(ctx context.Context, zoneID string, withRRSets bool) (*Zone, error) {
	var z Zone
	p := c.srv() + zonePath(zoneID)
	if !withRRSets {
		p += "?rrsets=false"
	}
	return &z, c.do(ctx, http.MethodGet, p, nil, &z)
}

func (c *Client) CreateZone(ctx context.Context, z *Zone) (*Zone, error) {
	var out Zone
	return &out, c.do(ctx, http.MethodPost, c.srv()+"/zones?rrsets=false", z, &out)
}

// UpdateZone modifies zone-level properties (kind, masters, dnssec flags, etc).
func (c *Client) UpdateZone(ctx context.Context, zoneID string, z map[string]any) error {
	return c.do(ctx, http.MethodPut, c.srv()+zonePath(zoneID), z, nil)
}

func (c *Client) DeleteZone(ctx context.Context, zoneID string) error {
	return c.do(ctx, http.MethodDelete, c.srv()+zonePath(zoneID), nil, nil)
}

func (c *Client) PatchRRSets(ctx context.Context, zoneID string, rrsets []RRSet) error {
	return c.do(ctx, http.MethodPatch, c.srv()+zonePath(zoneID), map[string]any{"rrsets": rrsets}, nil)
}

func (c *Client) Export(ctx context.Context, zoneID string) (string, error) {
	var s string
	if err := c.do(ctx, http.MethodGet, c.srv()+zonePath(zoneID)+"/export", nil, &s); err != nil {
		return "", err
	}
	// Newer releases wrap the zone text in JSON when JSON is acceptable.
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		var wrapped struct {
			Zone string `json:"zone"`
		}
		if json.Unmarshal([]byte(s), &wrapped) == nil {
			return wrapped.Zone, nil
		}
	}
	return s, nil
}

func (c *Client) Notify(ctx context.Context, zoneID string) error {
	return c.do(ctx, http.MethodPut, c.srv()+zonePath(zoneID)+"/notify", nil, nil)
}

func (c *Client) AXFRRetrieve(ctx context.Context, zoneID string) error {
	return c.do(ctx, http.MethodPut, c.srv()+zonePath(zoneID)+"/axfr-retrieve", nil, nil)
}

func (c *Client) Rectify(ctx context.Context, zoneID string) error {
	return c.do(ctx, http.MethodPut, c.srv()+zonePath(zoneID)+"/rectify", nil, nil)
}

// ---- DNSSEC ----

func (c *Client) CryptoKeys(ctx context.Context, zoneID string) ([]CryptoKey, error) {
	var k []CryptoKey
	return k, c.do(ctx, http.MethodGet, c.srv()+zonePath(zoneID)+"/cryptokeys", nil, &k)
}

func (c *Client) CreateCryptoKey(ctx context.Context, zoneID string, k CryptoKey) (*CryptoKey, error) {
	var out CryptoKey
	return &out, c.do(ctx, http.MethodPost, c.srv()+zonePath(zoneID)+"/cryptokeys", k, &out)
}

func (c *Client) SetCryptoKeyActive(ctx context.Context, zoneID string, id int, active bool) error {
	return c.do(ctx, http.MethodPut, fmt.Sprintf("%s%s/cryptokeys/%d", c.srv(), zonePath(zoneID), id),
		map[string]any{"active": active}, nil)
}

func (c *Client) DeleteCryptoKey(ctx context.Context, zoneID string, id int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("%s%s/cryptokeys/%d", c.srv(), zonePath(zoneID), id), nil, nil)
}

// ---- Metadata ----

func (c *Client) Metadata(ctx context.Context, zoneID string) ([]Metadata, error) {
	var m []Metadata
	return m, c.do(ctx, http.MethodGet, c.srv()+zonePath(zoneID)+"/metadata", nil, &m)
}

func (c *Client) SetMetadata(ctx context.Context, zoneID, kind string, values []string) error {
	if len(values) == 0 {
		err := c.do(ctx, http.MethodDelete, c.srv()+zonePath(zoneID)+"/metadata/"+url.PathEscape(kind), nil, nil)
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	return c.do(ctx, http.MethodPut, c.srv()+zonePath(zoneID)+"/metadata/"+url.PathEscape(kind),
		Metadata{Kind: kind, Metadata: values}, nil)
}

// ---- TSIG ----

func (c *Client) TSIGKeys(ctx context.Context) ([]TSIGKey, error) {
	var k []TSIGKey
	return k, c.do(ctx, http.MethodGet, c.srv()+"/tsigkeys", nil, &k)
}

func (c *Client) TSIGKey(ctx context.Context, id string) (*TSIGKey, error) {
	var k TSIGKey
	return &k, c.do(ctx, http.MethodGet, c.srv()+"/tsigkeys/"+url.PathEscape(id), nil, &k)
}

func (c *Client) CreateTSIGKey(ctx context.Context, k TSIGKey) (*TSIGKey, error) {
	var out TSIGKey
	return &out, c.do(ctx, http.MethodPost, c.srv()+"/tsigkeys", k, &out)
}

func (c *Client) DeleteTSIGKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, c.srv()+"/tsigkeys/"+url.PathEscape(id), nil, nil)
}
