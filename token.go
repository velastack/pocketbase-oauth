package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/security"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/types"
)

const (
	kindCode    = "code"
	kindAccess  = "access"
	kindRefresh = "refresh"

	// A client that lost the answer to a refresh (a dropped connection) asks
	// again with the token it still has. Within this window that is treated
	// as a retry that failed, not as a stolen token.
	refreshRetryGrace = time.Minute
)

// errGrant is a token request refused with invalid_grant or a sibling.
type errGrant struct {
	code        string
	description string
}

func (e *errGrant) Error() string { return e.description }

func invalidGrant(description string) error {
	return &errGrant{"invalid_grant", description}
}

func dateTime(t time.Time) types.DateTime {
	dt, _ := types.ParseDateTime(t)
	return dt
}

// authenticateClient resolves the client of a token or revocation request,
// from HTTP Basic or the form, and checks its secret if it has one.
func (p *plugin) authenticateClient(e *core.RequestEvent) (*Client, error) {
	clientID := e.Request.PostForm.Get("client_id")
	secret := e.Request.PostForm.Get("client_secret")
	if basicID, basicSecret, ok := e.Request.BasicAuth(); ok {
		// the credentials are form-encoded inside Basic (RFC 6749 2.3.1)
		if decoded, err := url.QueryUnescape(basicID); err == nil {
			basicID = decoded
		}
		if decoded, err := url.QueryUnescape(basicSecret); err == nil {
			basicSecret = decoded
		}
		clientID, secret = basicID, basicSecret
	}

	client, err := p.findClient(e.App, clientID)
	if err != nil {
		return nil, err
	}
	if client.AuthMethod != authNone && !client.checkSecret(secret) {
		return nil, invalidClient("client authentication failed")
	}
	return client, nil
}

func verifyPKCE(verifier string, challenge string) bool {
	if !verifierRe.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// token implements the token endpoint: the authorization_code and
// refresh_token grants.
func (p *plugin) token(e *core.RequestEvent) error {
	if err := e.Request.ParseForm(); err != nil {
		return oauthError(e, http.StatusBadRequest, "invalid_request", "The body must be form encoded.")
	}
	form := e.Request.PostForm

	client, err := p.authenticateClient(e)
	if err != nil {
		var invalid *errInvalidClient
		if errors.As(err, &invalid) {
			return oauthError(e, http.StatusUnauthorized, "invalid_client", invalid.reason)
		}
		return err
	}

	var response map[string]any
	switch form.Get("grant_type") {
	case "authorization_code":
		response, err = p.redeemCode(e.App, client, form)
	case "refresh_token":
		response, err = p.refresh(e.App, client, form)
	default:
		return oauthError(e, http.StatusBadRequest, "unsupported_grant_type", "Only the authorization_code and refresh_token grants are supported.")
	}
	if err != nil {
		var refused *errGrant
		if errors.As(err, &refused) {
			return oauthError(e, http.StatusBadRequest, refused.code, refused.description)
		}
		return err
	}

	e.Response.Header().Set("Cache-Control", "no-store")
	e.Response.Header().Set("Pragma", "no-cache")
	return e.JSON(http.StatusOK, response)
}

// redeemCode exchanges an authorization code for tokens. A code works once:
// presenting it again revokes what the first use was given.
func (p *plugin) redeemCode(app core.App, client *Client, form url.Values) (map[string]any, error) {
	code := form.Get("code")
	if code == "" {
		return nil, &errGrant{"invalid_request", "code is required."}
	}

	var response map[string]any
	var refused error
	err := app.RunInTransaction(func(txApp core.App) error {
		record, _ := txApp.FindFirstRecordByData(CollectionNameTokens, "hash", hashToken(code))
		if record == nil || record.GetString("kind") != kindCode {
			refused = invalidGrant("The authorization code is invalid.")
			return nil
		}
		if !record.GetDateTime("used").IsZero() {
			refused = invalidGrant("The authorization code was already used.")
			return revokeGrant(txApp, record.GetString("grantRef"))
		}
		if record.GetDateTime("expires").Time().Before(time.Now()) {
			refused = invalidGrant("The authorization code has expired.")
			return nil
		}

		var bound codeBinding
		if err := record.UnmarshalJSONField("request", &bound); err != nil {
			return err
		}
		if bound.ClientID != client.ID {
			refused = invalidGrant("The authorization code was issued to another client.")
			return nil
		}
		if form.Get("redirect_uri") != bound.RedirectURI {
			refused = invalidGrant("redirect_uri does not match the authorization request.")
			return nil
		}
		if !verifyPKCE(form.Get("code_verifier"), bound.CodeChallenge) {
			refused = invalidGrant("The PKCE code_verifier does not match.")
			return nil
		}
		resource := bound.Resource
		if requested := form.Get("resource"); requested != "" && requested != resource {
			if resource != "" || validateResource(requested) != nil {
				refused = &errGrant{"invalid_target", "resource does not match the authorization request."}
				return nil
			}
			resource = requested
		}
		if _, err := txApp.FindRecordById(bound.CollectionRef, bound.RecordRef); err != nil {
			refused = invalidGrant("The user no longer exists.")
			return nil
		}

		// approving a client again replaces what it had for that resource
		if err := deleteGrantsWhere(txApp, dbx.HashExp{
			"clientId":      client.ID,
			"collectionRef": bound.CollectionRef,
			"recordRef":     bound.RecordRef,
			"resource":      resource,
		}); err != nil {
			return err
		}

		grants, err := txApp.FindCollectionByNameOrId(CollectionNameGrants)
		if err != nil {
			return err
		}
		grant := core.NewRecord(grants)
		grant.Set("clientId", client.ID)
		grant.Set("collectionRef", bound.CollectionRef)
		grant.Set("recordRef", bound.RecordRef)
		grant.Set("scope", record.GetString("scope"))
		grant.Set("resource", resource)
		grant.Set("lastUsed", dateTime(time.Now()))
		if err := txApp.Save(grant); err != nil {
			return err
		}

		record.Set("used", dateTime(time.Now()))
		record.Set("grantRef", grant.Id)
		if err := txApp.Save(record); err != nil {
			return err
		}

		response, err = p.issueTokens(txApp, grant.Id, grant.GetString("scope"))
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, refused
}

// refresh exchanges a refresh token for a new pair. Each refresh token works
// once; a second use after the retry window means it was copied, and revokes
// the grant.
func (p *plugin) refresh(app core.App, client *Client, form url.Values) (map[string]any, error) {
	token := form.Get("refresh_token")
	if token == "" {
		return nil, &errGrant{"invalid_request", "refresh_token is required."}
	}

	var response map[string]any
	var refused error
	err := app.RunInTransaction(func(txApp core.App) error {
		record, _ := txApp.FindFirstRecordByData(CollectionNameTokens, "hash", hashToken(token))
		if record == nil || record.GetString("kind") != kindRefresh {
			refused = invalidGrant("The refresh token is invalid.")
			return nil
		}
		grant, err := txApp.FindRecordById(CollectionNameGrants, record.GetString("grantRef"))
		if err != nil || grant.GetString("clientId") != client.ID {
			refused = invalidGrant("The refresh token is invalid.")
			return nil
		}
		if used := record.GetDateTime("used"); !used.IsZero() {
			refused = invalidGrant("The refresh token was already used.")
			if time.Since(used.Time()) > refreshRetryGrace {
				return revokeGrant(txApp, grant.Id)
			}
			return nil
		}
		if record.GetDateTime("expires").Time().Before(time.Now()) {
			refused = invalidGrant("The refresh token has expired.")
			return nil
		}
		if requested := form.Get("resource"); requested != "" && requested != grant.GetString("resource") {
			refused = &errGrant{"invalid_target", "resource does not match the grant."}
			return nil
		}
		scope := grant.GetString("scope")
		if requested := form.Get("scope"); requested != "" {
			narrowed, err := normalizeScope(requested)
			if err != nil || !scopeWithin(narrowed, scope) {
				refused = &errGrant{"invalid_scope", "scope exceeds what was granted."}
				return nil
			}
			scope = narrowed
		}
		if _, err := txApp.FindRecordById(grant.GetString("collectionRef"), grant.GetString("recordRef")); err != nil {
			refused = invalidGrant("The user no longer exists.")
			return revokeGrant(txApp, grant.Id)
		}

		record.Set("used", dateTime(time.Now()))
		if err := txApp.Save(record); err != nil {
			return err
		}
		// the access tokens of the previous pair end with it
		if _, err := txApp.DB().Delete(CollectionNameTokens, dbx.HashExp{"grantRef": grant.Id, "kind": kindAccess}).Execute(); err != nil {
			return err
		}
		grant.Set("lastUsed", dateTime(time.Now()))
		if err := txApp.Save(grant); err != nil {
			return err
		}

		response, err = p.issueTokens(txApp, grant.Id, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, refused
}

// issueTokens stores a new access and refresh token for a grant and returns
// the token response.
func (p *plugin) issueTokens(txApp core.App, grantID string, scope string) (map[string]any, error) {
	collection, err := txApp.FindCollectionByNameOrId(CollectionNameTokens)
	if err != nil {
		return nil, err
	}

	access := "oat_" + security.RandomString(48)
	refresh := "ort_" + security.RandomString(48)
	now := time.Now()

	for _, token := range []struct {
		value string
		kind  string
		ttl   time.Duration
	}{
		{access, kindAccess, p.config.AccessTokenTTL},
		{refresh, kindRefresh, p.config.RefreshTokenTTL},
	} {
		record := core.NewRecord(collection)
		record.Set("hash", hashToken(token.value))
		record.Set("kind", token.kind)
		record.Set("grantRef", grantID)
		record.Set("scope", scope)
		record.Set("expires", dateTime(now.Add(token.ttl)))
		if err := txApp.Save(record); err != nil {
			return nil, err
		}
	}

	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(p.config.AccessTokenTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         scope,
	}, nil
}

// revoke implements token revocation (RFC 7009). Revoking a refresh token
// ends the grant; revoking an access token ends that token.
func (p *plugin) revoke(e *core.RequestEvent) error {
	if err := e.Request.ParseForm(); err != nil {
		return oauthError(e, http.StatusBadRequest, "invalid_request", "The body must be form encoded.")
	}

	client, err := p.authenticateClient(e)
	if err != nil {
		var invalid *errInvalidClient
		if errors.As(err, &invalid) {
			return oauthError(e, http.StatusUnauthorized, "invalid_client", invalid.reason)
		}
		return err
	}

	// an unknown token is not an error: the caller wanted it gone and it is
	record, _ := e.App.FindFirstRecordByData(CollectionNameTokens, "hash", hashToken(e.Request.PostForm.Get("token")))
	if record != nil && record.GetString("kind") != kindCode {
		grant, err := e.App.FindRecordById(CollectionNameGrants, record.GetString("grantRef"))
		if err == nil && grant.GetString("clientId") == client.ID {
			if record.GetString("kind") == kindRefresh {
				err = revokeGrant(e.App, grant.Id)
			} else {
				err = e.App.Delete(record)
			}
			if err != nil {
				return err
			}
		}
	}

	e.Response.Header().Set("Cache-Control", "no-store")
	return e.NoContent(http.StatusOK)
}

// introspect tells a resource server whether an access token is valid and
// who and what it stands for (RFC 7662). Superusers only: the resource server
// is the app that already holds a superuser client.
func (p *plugin) introspect(e *core.RequestEvent) error {
	form := struct {
		Token string `json:"token" form:"token"`
	}{}
	if err := e.BindBody(&form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	inactive := map[string]any{"active": false}
	e.Response.Header().Set("Cache-Control", "no-store")

	record, _ := e.App.FindFirstRecordByData(CollectionNameTokens, "hash", hashToken(form.Token))
	if form.Token == "" || record == nil || record.GetString("kind") != kindAccess {
		return e.JSON(http.StatusOK, inactive)
	}
	expires := record.GetDateTime("expires").Time()
	if expires.Before(time.Now()) {
		return e.JSON(http.StatusOK, inactive)
	}
	grant, err := e.App.FindRecordById(CollectionNameGrants, record.GetString("grantRef"))
	if err != nil {
		return e.JSON(http.StatusOK, inactive)
	}
	user, err := e.App.FindRecordById(grant.GetString("collectionRef"), grant.GetString("recordRef"))
	if err != nil {
		return e.JSON(http.StatusOK, inactive)
	}

	// kept roughly current without a write on every request
	if time.Since(grant.GetDateTime("lastUsed").Time()) > time.Hour {
		grant.Set("lastUsed", dateTime(time.Now()))
		if err := e.App.Save(grant); err != nil {
			e.App.Logger().Warn("Failed to update an OAuth grant's last use", "error", err)
		}
	}

	response := map[string]any{
		"active":          true,
		"token_type":      "Bearer",
		"scope":           record.GetString("scope"),
		"client_id":       grant.GetString("clientId"),
		"sub":             user.Id,
		"collection_id":   user.Collection().Id,
		"collection_name": user.Collection().Name,
		"grant_id":        grant.Id,
		"exp":             expires.Unix(),
		"iat":             record.GetDateTime("created").Time().Unix(),
		"iss":             p.issuer(e.App),
	}
	if resource := grant.GetString("resource"); resource != "" {
		response["aud"] = resource
	}
	return e.JSON(http.StatusOK, response)
}
