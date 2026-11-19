package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/security"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/types"
)

// authRequest is an authorization request: the query the authorization
// endpoint was opened with, under the parameter names of RFC 6749.
type authRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
}

// consentDecision is what the consent page posts for the signed-in user.
type consentDecision struct {
	authRequest

	// Approve is false when the person declined.
	Approve bool `json:"approve"`

	// GrantedScope is what the person agreed to, when the page let them
	// choose or the request named no scope. Defaults to the requested scope.
	GrantedScope *string `json:"granted_scope"`

	// Issuer overrides the issuer sent back to the client, for an app that
	// serves one PocketBase under several origins.
	Issuer string `json:"issuer"`
}

// codeBinding is what an authorization code is tied to until it is redeemed.
type codeBinding struct {
	ClientID      string `json:"clientId"`
	RedirectURI   string `json:"redirectUri"`
	CodeChallenge string `json:"codeChallenge"`
	Resource      string `json:"resource"`
	CollectionRef string `json:"collectionRef"`
	RecordRef     string `json:"recordRef"`
}

// requestError is a problem with an authorization request that is reported
// to the client, by redirect, as RFC 6749 4.1.2.1 describes.
type requestError struct {
	code        string
	description string
}

var (
	scopeTokenRe = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
	// base64url of a SHA-256 digest
	challengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	verifierRe  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// normalizeScope validates a scope string and removes its duplicates.
func normalizeScope(scope string) (string, error) {
	if len(scope) > 2000 {
		return "", errors.New("scope is too long")
	}
	seen := map[string]bool{}
	tokens := []string{}
	for _, token := range strings.Fields(scope) {
		if !scopeTokenRe.MatchString(token) {
			return "", errors.New("scope has an invalid character")
		}
		if !seen[token] {
			seen[token] = true
			tokens = append(tokens, token)
		}
	}
	return strings.Join(tokens, " "), nil
}

// scopeWithin reports whether every token of scope is in allowed.
func scopeWithin(scope string, allowed string) bool {
	have := map[string]bool{}
	for _, token := range strings.Fields(allowed) {
		have[token] = true
	}
	for _, token := range strings.Fields(scope) {
		if !have[token] {
			return false
		}
	}
	return true
}

// validateResource checks a resource indicator (RFC 8707): an absolute URI
// without a fragment. Which resource a token is good for is enforced by the
// resource server, which is told the token's resource on introspection.
func validateResource(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("resource must be an absolute URI without a fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u)) {
		return errors.New("resource must be an https URI")
	}
	return nil
}

// validateAuthRequest checks an authorization request. A non-nil error means
// the client or its redirect URI could not be trusted, so the problem must be
// shown to the person and not sent anywhere. A requestError is safe to report
// to the client by redirect.
func (p *plugin) validateAuthRequest(app core.App, req *authRequest) (*Client, *requestError, error) {
	client, err := p.findClient(app, req.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if !client.allowsRedirect(req.RedirectURI) {
		return nil, nil, invalidClient("redirect_uri is not registered for this client")
	}

	if req.ResponseType != "code" {
		return client, &requestError{"unsupported_response_type", "Only the code response type is supported."}, nil
	}
	if req.CodeChallengeMethod != "S256" || !challengeRe.MatchString(req.CodeChallenge) {
		return client, &requestError{"invalid_request", "A PKCE code_challenge with the S256 method is required."}, nil
	}
	if len(req.State) > 2000 {
		return client, &requestError{"invalid_request", "state is too long."}, nil
	}
	scope, err := normalizeScope(req.Scope)
	if err != nil {
		return client, &requestError{"invalid_scope", err.Error()}, nil
	}
	req.Scope = scope
	if err := validateResource(req.Resource); err != nil {
		return client, &requestError{"invalid_target", err.Error()}, nil
	}

	return client, nil, nil
}

// redirectWith adds the response parameters to a redirect URI, keeping the
// query it already has.
func redirectWith(redirectURI string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	query := u.Query()
	for key, value := range params {
		if value != "" {
			query.Set(key, value)
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func (p *plugin) errorRedirect(req *authRequest, issuer string, problem *requestError) string {
	return redirectWith(req.RedirectURI, map[string]string{
		"error":             problem.code,
		"error_description": problem.description,
		"state":             req.State,
		"iss":               issuer,
	})
}

func clientView(client *Client) map[string]any {
	return map[string]any{
		"id":      client.ID,
		"name":    client.Name,
		"uri":     client.URI,
		"logoUri": client.LogoURI,
		// a client names itself, so the page should also show where the
		// person is sent back to
		"verified": false,
	}
}

// describeConsent validates an authorization request and returns what the
// consent page shows. It needs no auth: it runs before the person signs in,
// and reveals nothing the client did not publish itself.
func (p *plugin) describeConsent(e *core.RequestEvent) error {
	query := e.Request.URL.Query()
	req := &authRequest{
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		ResponseType:        query.Get("response_type"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		State:               query.Get("state"),
		Scope:               query.Get("scope"),
		Resource:            query.Get("resource"),
	}
	issuer := p.issuer(e.App)
	if override := query.Get("issuer"); override != "" {
		issuer = override
	}

	if isMetadataURL(req.ClientID) {
		if ok := p.limiter.allow("consent:"+e.RealIP(), 60, time.Minute, time.Now()); !ok {
			return oauthError(e, http.StatusTooManyRequests, "temporarily_unavailable", "Too many requests, try again later.")
		}
	}

	client, problem, err := p.validateAuthRequest(e.App, req)
	if err != nil {
		var invalid *errInvalidClient
		if errors.As(err, &invalid) {
			return oauthError(e, http.StatusBadRequest, "invalid_client", invalid.reason)
		}
		return err
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	if problem != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{
			"error":             problem.code,
			"error_description": problem.description,
			"redirectTo":        p.errorRedirect(req, issuer, problem),
		})
	}

	redirect, _ := url.Parse(req.RedirectURI)
	return e.JSON(http.StatusOK, map[string]any{
		"client":       clientView(client),
		"redirectUri":  req.RedirectURI,
		"redirectHost": redirect.Host,
		"scope":        req.Scope,
		"resource":     req.Resource,
	})
}

// decideConsent records the signed-in user's decision and returns where to
// send them: back to the client with an authorization code, or with
// access_denied.
func (p *plugin) decideConsent(e *core.RequestEvent) error {
	if e.Auth == nil || e.Auth.IsSuperuser() {
		return e.ForbiddenError("Superusers cannot authorize OAuth clients.", nil)
	}

	decision := &consentDecision{}
	body, err := io.ReadAll(io.LimitReader(e.Request.Body, 64<<10))
	if err != nil || json.Unmarshal(body, decision) != nil {
		return e.BadRequestError("The body must be a JSON object.", nil)
	}
	req := &decision.authRequest
	issuer := p.issuer(e.App)
	if decision.Issuer != "" {
		issuer = strings.TrimRight(decision.Issuer, "/")
	}

	client, problem, err := p.validateAuthRequest(e.App, req)
	if err != nil {
		var invalid *errInvalidClient
		if errors.As(err, &invalid) {
			return oauthError(e, http.StatusBadRequest, "invalid_client", invalid.reason)
		}
		return err
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	if problem == nil && !decision.Approve {
		problem = &requestError{"access_denied", "The request was declined."}
	}

	scope := req.Scope
	if problem == nil && decision.GrantedScope != nil {
		if scope, err = normalizeScope(*decision.GrantedScope); err != nil {
			problem = &requestError{"invalid_scope", err.Error()}
		}
	}
	if problem != nil {
		return e.JSON(http.StatusOK, map[string]string{"redirectTo": p.errorRedirect(req, issuer, problem)})
	}

	collection, err := e.App.FindCollectionByNameOrId(CollectionNameTokens)
	if err != nil {
		return err
	}
	code := "oac_" + security.RandomString(48)
	expires, _ := types.ParseDateTime(time.Now().Add(p.config.CodeTTL))

	record := core.NewRecord(collection)
	record.Set("hash", hashToken(code))
	record.Set("kind", kindCode)
	record.Set("scope", scope)
	record.Set("expires", expires)
	record.Set("request", codeBinding{
		ClientID:      client.ID,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		Resource:      req.Resource,
		CollectionRef: e.Auth.Collection().Id,
		RecordRef:     e.Auth.Id,
	})
	if err := e.App.Save(record); err != nil {
		return err
	}

	return e.JSON(http.StatusOK, map[string]string{
		"redirectTo": redirectWith(req.RedirectURI, map[string]string{
			"code":  code,
			"state": req.State,
			"iss":   issuer,
		}),
	})
}
