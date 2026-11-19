package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/security"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/types"
)

const (
	sourceDCR  = "dcr"
	sourceCIMD = "cimd"

	authNone        = "none"
	authSecretPost  = "client_secret_post"
	authSecretBasic = "client_secret_basic"

	maxRedirectURIs = 20
	// the Client ID Metadata Document draft recommends refusing documents
	// over 5 kB; a little room is left for long redirect lists
	maxMetadataBytes = 16 << 10

	metadataMinFresh     = 5 * time.Minute
	metadataDefaultFresh = time.Hour
	metadataMaxFresh     = 24 * time.Hour
	// how long a document that can no longer be fetched keeps working, so a
	// client's outage doesn't sign its users out
	metadataStaleFor = 7 * 24 * time.Hour
)

// Client is an application that may ask users for access.
type Client struct {
	ID           string
	Source       string
	AuthMethod   string
	Name         string
	URI          string
	LogoURI      string
	RedirectURIs []string

	secretHash string
}

// errInvalidClient is returned when a client_id names no usable client.
type errInvalidClient struct{ reason string }

func (e *errInvalidClient) Error() string { return e.reason }

func invalidClient(format string, args ...any) error {
	return &errInvalidClient{fmt.Sprintf(format, args...)}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func clientFromRecord(record *core.Record) *Client {
	c := &Client{
		ID:         record.GetString("clientId"),
		Source:     record.GetString("source"),
		AuthMethod: record.GetString("authMethod"),
		Name:       record.GetString("name"),
		URI:        record.GetString("uri"),
		LogoURI:    record.GetString("logoUri"),
		secretHash: record.GetString("secretHash"),
	}
	_ = record.UnmarshalJSONField("redirectUris", &c.RedirectURIs)
	return c
}

// isMetadataURL reports whether a client_id is a Client ID Metadata Document
// URL rather than an id issued here.
func isMetadataURL(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// findClient resolves a client_id: a registered client, or a Client ID
// Metadata Document, fetched when the copy held is no longer fresh.
func (p *plugin) findClient(app core.App, clientID string) (*Client, error) {
	if clientID == "" || len(clientID) > 2048 {
		return nil, invalidClient("missing or malformed client_id")
	}

	record, _ := app.FindFirstRecordByData(CollectionNameClients, "clientId", clientID)

	if !isMetadataURL(clientID) {
		if record == nil || record.GetString("source") != sourceDCR {
			return nil, invalidClient("unknown client")
		}
		return clientFromRecord(record), nil
	}

	now := time.Now()
	if record != nil && record.GetDateTime("freshUntil").Time().After(now) {
		return clientFromRecord(record), nil
	}

	client, fresh, err := p.fetchMetadataDocument(clientID)
	if err != nil {
		if record != nil && record.GetDateTime("freshUntil").Time().Add(metadataStaleFor).After(now) {
			app.Logger().Warn("Using a stale OAuth client metadata document", "clientId", clientID, "error", err)
			return clientFromRecord(record), nil
		}
		return nil, err
	}

	if record == nil {
		collection, err := app.FindCollectionByNameOrId(CollectionNameClients)
		if err != nil {
			return nil, err
		}
		record = core.NewRecord(collection)
		record.Set("clientId", client.ID)
		record.Set("source", sourceCIMD)
	}
	record.Set("authMethod", client.AuthMethod)
	record.Set("name", client.Name)
	record.Set("uri", client.URI)
	record.Set("logoUri", client.LogoURI)
	record.Set("redirectUris", client.RedirectURIs)
	freshUntil, _ := types.ParseDateTime(now.Add(fresh))
	record.Set("freshUntil", freshUntil)
	if err := app.Save(record); err != nil {
		// two requests for a new client can race to store it; the document
		// was valid either way
		app.Logger().Debug("Failed to store an OAuth client metadata document", "clientId", clientID, "error", err)
	}

	return client, nil
}

// clientMetadata is the subset of RFC 7591 client metadata that is read from
// a registration request or a Client ID Metadata Document.
type clientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientSecret            string   `json:"client_secret"`
}

// validateMetadataURL checks a client_id against the rules for Client ID
// Metadata Document URLs.
func validateMetadataURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, invalidClient("client_id must be an https URL")
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, invalidClient("client_id must not have credentials or a fragment")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, invalidClient("client_id must have a path")
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return nil, invalidClient("client_id must not have dot path segments")
		}
	}
	return u, nil
}

var maxAgeRe = regexp.MustCompile(`(?i)\bmax-age=(\d+)`)

// freshFor reads how long a fetched document may be used from its cache
// headers, within fixed bounds.
func freshFor(header http.Header) time.Duration {
	cacheControl := header.Get("Cache-Control")
	if strings.Contains(strings.ToLower(cacheControl), "no-store") {
		return metadataMinFresh
	}
	if match := maxAgeRe.FindStringSubmatch(cacheControl); match != nil {
		if seconds, err := strconv.Atoi(match[1]); err == nil {
			return min(max(time.Duration(seconds)*time.Second, metadataMinFresh), metadataMaxFresh)
		}
	}
	return metadataDefaultFresh
}

// fetchMetadataDocument fetches and validates a Client ID Metadata Document.
func (p *plugin) fetchMetadataDocument(clientID string) (*Client, time.Duration, error) {
	if _, err := validateMetadataURL(clientID); err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, invalidClient("client_id is not a fetchable URL")
	}
	req.Header.Set("Accept", "application/json")

	res, err := p.config.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, invalidClient("the client metadata document could not be fetched")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, 0, invalidClient("the client metadata document answered %d", res.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, 0, invalidClient("the client metadata document could not be read")
	}
	if len(raw) > maxMetadataBytes {
		return nil, 0, invalidClient("the client metadata document is too large")
	}

	var doc clientMetadata
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, invalidClient("the client metadata document is not valid JSON")
	}
	if doc.ClientID != clientID {
		return nil, 0, invalidClient("the client metadata document's client_id does not match its URL")
	}
	if strings.TrimSpace(doc.ClientName) == "" {
		return nil, 0, invalidClient("the client metadata document has no client_name")
	}
	// a document is public, so it cannot hold or use a shared secret
	if doc.ClientSecret != "" || (doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != authNone) {
		return nil, 0, invalidClient("only public clients (token_endpoint_auth_method none) are supported with a metadata document")
	}
	if err := validateRedirectURIs(doc.RedirectURIs); err != nil {
		return nil, 0, invalidClient("%s", err.Error())
	}

	return &Client{
		ID:           clientID,
		Source:       sourceCIMD,
		AuthMethod:   authNone,
		Name:         truncate(strings.TrimSpace(doc.ClientName), 200),
		URI:          safeLink(doc.ClientURI),
		LogoURI:      safeLink(doc.LogoURI),
		RedirectURIs: doc.RedirectURIs,
	}, freshFor(res.Header), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// safeLink keeps a link a consent page may show: an https URL, or nothing.
func safeLink(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(raw) > 2048 {
		return ""
	}
	return raw
}

// isLoopback reports whether a redirect URI points at this machine, which is
// the only place plain http is accepted (RFC 8252).
func isLoopback(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// schemes that run or read something in the browser instead of handing the
// code to an application
var forbiddenRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "vbscript": true, "file": true, "blob": true, "about": true,
}

func validateRedirectURI(raw string) error {
	if raw == "" || len(raw) > 2048 {
		return errors.New("redirect_uris must be non-empty URIs")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("redirect URI %q is not an absolute URI", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect URI %q must not have a fragment", raw)
	}
	switch {
	case u.Scheme == "https":
		if u.Host == "" {
			return fmt.Errorf("redirect URI %q has no host", raw)
		}
	case u.Scheme == "http":
		if !isLoopback(u) {
			return fmt.Errorf("redirect URI %q must use https", raw)
		}
	case forbiddenRedirectSchemes[strings.ToLower(u.Scheme)]:
		return fmt.Errorf("redirect URI %q uses a scheme that is not allowed", raw)
	}
	return nil
}

func validateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	if len(uris) > maxRedirectURIs {
		return fmt.Errorf("at most %d redirect URIs are allowed", maxRedirectURIs)
	}
	for _, raw := range uris {
		if err := validateRedirectURI(raw); err != nil {
			return err
		}
	}
	return nil
}

// allowsRedirect reports whether the client registered redirectURI. The match
// is exact, except that a loopback redirect may use any port: native apps
// listen on whichever is free (RFC 8252 7.3).
func (c *Client) allowsRedirect(redirectURI string) bool {
	if redirectURI == "" {
		return false
	}
	for _, registered := range c.RedirectURIs {
		if registered == redirectURI {
			return true
		}
	}

	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "http" || !isLoopback(u) || u.Fragment != "" {
		return false
	}
	for _, registered := range c.RedirectURIs {
		r, err := url.Parse(registered)
		if err != nil || r.Scheme != "http" || !isLoopback(r) {
			continue
		}
		if r.Hostname() == u.Hostname() && r.EscapedPath() == u.EscapedPath() && r.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

// checkSecret verifies the secret of a confidential client.
func (c *Client) checkSecret(secret string) bool {
	if c.secretHash == "" || secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(c.secretHash)) == 1
}

// registerClient implements dynamic client registration (RFC 7591).
//
// Anyone can register, as the protocol intends: a client is only a name and
// the redirect URIs a code may be sent to, and gets nothing until a user
// approves it. Registrations are rate limited per address and the ones nobody
// approved are removed after a while.
func (p *plugin) registerClient(e *core.RequestEvent) error {
	if ok := p.limiter.allow("register:"+e.RealIP(), 20, time.Hour, time.Now()); !ok {
		return oauthError(e, http.StatusTooManyRequests, "invalid_client_metadata", "Too many registrations, try again later.")
	}

	var doc clientMetadata
	body, err := io.ReadAll(io.LimitReader(e.Request.Body, maxMetadataBytes+1))
	if err != nil || len(body) > maxMetadataBytes || json.Unmarshal(body, &doc) != nil {
		return oauthError(e, http.StatusBadRequest, "invalid_client_metadata", "The body must be a JSON object of client metadata.")
	}

	if err := validateRedirectURIs(doc.RedirectURIs); err != nil {
		return oauthError(e, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
	}
	for _, grant := range doc.GrantTypes {
		if grant != "authorization_code" && grant != "refresh_token" {
			return oauthError(e, http.StatusBadRequest, "invalid_client_metadata", "Only the authorization_code and refresh_token grant types are supported.")
		}
	}
	for _, responseType := range doc.ResponseTypes {
		if responseType != "code" {
			return oauthError(e, http.StatusBadRequest, "invalid_client_metadata", "Only the code response type is supported.")
		}
	}

	authMethod := doc.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = authNone
	}
	if authMethod != authNone && authMethod != authSecretPost && authMethod != authSecretBasic {
		return oauthError(e, http.StatusBadRequest, "invalid_client_metadata", "Unsupported token_endpoint_auth_method.")
	}

	collection, err := e.App.FindCollectionByNameOrId(CollectionNameClients)
	if err != nil {
		return err
	}

	clientID := security.RandomString(32)
	name := truncate(strings.TrimSpace(doc.ClientName), 200)

	record := core.NewRecord(collection)
	record.Set("clientId", clientID)
	record.Set("source", sourceDCR)
	record.Set("authMethod", authMethod)
	record.Set("name", name)
	record.Set("uri", safeLink(doc.ClientURI))
	record.Set("logoUri", safeLink(doc.LogoURI))
	record.Set("redirectUris", doc.RedirectURIs)

	response := map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                name,
		"redirect_uris":              doc.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
	}
	if authMethod != authNone {
		secret := security.RandomString(48)
		record.Set("secretHash", hashToken(secret))
		response["client_secret"] = secret
		response["client_secret_expires_at"] = 0
	}

	if err := e.App.Save(record); err != nil {
		return err
	}

	e.Response.Header().Set("Cache-Control", "no-store")
	return e.JSON(http.StatusCreated, response)
}

// publicHTTPClient returns the client that fetches metadata documents. The
// URL comes from whoever starts an authorization, so it must not be a way to
// reach this machine or its network: the address is checked when the
// connection is made (after DNS, so a name cannot resolve to something else
// in between) and redirects are not followed.
func publicHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !isPublicIP(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// no proxy: one would make the connection, and the check, its own
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || cgnat.Contains(ip))
}
