package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tests"
)

const (
	testIssuer   = "https://app.example.com"
	testRedirect = "https://client.example.com/callback"
	testResource = "https://app.example.com/mcp"
	testVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
)

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type testEnv struct {
	t              *testing.T
	app            *tests.TestApp
	handler        http.Handler
	plugin         *plugin
	user           *core.Record
	userToken      string
	superuserToken string
}

type testResponse struct {
	status int
	header http.Header
	body   map[string]any
	raw    string
}

func (r testResponse) str(key string) string {
	value, _ := r.body[key].(string)
	return value
}

func newTestEnv(t *testing.T, config Config) *testEnv {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)

	if config.Issuer == "" {
		config.Issuer = testIssuer
	}
	env := &testEnv{t: t, app: app}
	env.plugin, err = register(app, config)
	if err != nil {
		t.Fatal(err)
	}

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	user := core.NewRecord(users)
	user.SetEmail("oauth-user@example.com")
	user.SetPassword("1234567890")
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}
	env.user = user
	if env.userToken, err = user.NewAuthToken(); err != nil {
		t.Fatal(err)
	}

	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if env.superuserToken, err = superuser.NewAuthToken(); err != nil {
		t.Fatal(err)
	}

	baseRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	serveEvent := &core.ServeEvent{App: app, Router: baseRouter}
	err = app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		mux, err := e.Router.BuildMux()
		env.handler = mux
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	return env
}

func (env *testEnv) send(req *http.Request) testResponse {
	env.t.Helper()
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	raw, _ := io.ReadAll(rec.Body)
	res := testResponse{status: rec.Code, header: rec.Header(), raw: string(raw), body: map[string]any{}}
	_ = json.Unmarshal(raw, &res.body)
	return res
}

func (env *testEnv) json(method string, path string, body any, token string) testResponse {
	env.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			env.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	return env.send(req)
}

func (env *testEnv) form(path string, values url.Values) testResponse {
	env.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return env.send(req)
}

// registerTestClient registers a public client with the test redirect URI.
func (env *testEnv) registerTestClient(extra map[string]any) testResponse {
	env.t.Helper()
	body := map[string]any{
		"client_name":   "Test Client",
		"redirect_uris": []string{testRedirect, "http://127.0.0.1:3000/callback"},
	}
	for key, value := range extra {
		body[key] = value
	}
	res := env.json(http.MethodPost, "/api/oauth/register", body, "")
	if res.status != http.StatusCreated {
		env.t.Fatalf("Expected the client to be registered, got %d %s", res.status, res.raw)
	}
	return res
}

func authParams(clientID string) map[string]any {
	return map[string]any{
		"client_id":             clientID,
		"redirect_uri":          testRedirect,
		"response_type":         "code",
		"code_challenge":        challengeOf(testVerifier),
		"code_challenge_method": "S256",
		"state":                 "xyz",
		"scope":                 "content:read content:write",
		"resource":              testResource,
	}
}

// approve posts the user's yes and returns the code from the redirect.
func (env *testEnv) approve(params map[string]any) string {
	env.t.Helper()
	body := map[string]any{"approve": true}
	for key, value := range params {
		body[key] = value
	}
	res := env.json(http.MethodPost, "/api/oauth/consent", body, env.userToken)
	if res.status != http.StatusOK {
		env.t.Fatalf("Expected the consent to be recorded, got %d %s", res.status, res.raw)
	}
	redirect, err := url.Parse(res.str("redirectTo"))
	if err != nil {
		env.t.Fatal(err)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		env.t.Fatalf("Expected a code in %q", res.str("redirectTo"))
	}
	return code
}

func (env *testEnv) exchange(clientID string, code string) testResponse {
	env.t.Helper()
	return env.form("/api/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {testVerifier},
		"resource":      {testResource},
	})
}

func (env *testEnv) introspect(token string) testResponse {
	env.t.Helper()
	return env.json(http.MethodPost, "/api/oauth/introspect", map[string]string{"token": token}, env.superuserToken)
}

// authorized runs the whole flow and returns the client id and token response.
func (env *testEnv) authorized() (string, testResponse) {
	env.t.Helper()
	clientID := env.registerTestClient(nil).str("client_id")
	res := env.exchange(clientID, env.approve(authParams(clientID)))
	if res.status != http.StatusOK {
		env.t.Fatalf("Expected tokens, got %d %s", res.status, res.raw)
	}
	return clientID, res
}

func TestMetadata(t *testing.T) {
	env := newTestEnv(t, Config{})

	res := env.json(http.MethodGet, "/.well-known/oauth-authorization-server", nil, "")
	if res.status != http.StatusOK {
		t.Fatalf("Expected 200, got %d %s", res.status, res.raw)
	}
	expected := map[string]string{
		"issuer":                 testIssuer,
		"authorization_endpoint": testIssuer + "/oauth/authorize",
		"token_endpoint":         testIssuer + "/api/oauth/token",
		"registration_endpoint":  testIssuer + "/api/oauth/register",
	}
	for key, value := range expected {
		if res.str(key) != value {
			t.Errorf("Expected %s to be %q, got %q", key, value, res.str(key))
		}
	}
	for _, flag := range []string{"client_id_metadata_document_supported", "authorization_response_iss_parameter_supported"} {
		if res.body[flag] != true {
			t.Errorf("Expected %s to be true", flag)
		}
	}
}

func TestMetadataWithoutDynamicRegistration(t *testing.T) {
	env := newTestEnv(t, Config{DisableDynamicRegistration: true})

	res := env.json(http.MethodGet, "/.well-known/oauth-authorization-server", nil, "")
	if _, ok := res.body["registration_endpoint"]; ok {
		t.Fatal("Expected no registration_endpoint")
	}
	if res := env.json(http.MethodPost, "/api/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}}, ""); res.status != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", res.status)
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID := env.registerTestClient(nil).str("client_id")

	// the consent page describes the request before anyone signs in
	query := url.Values{}
	for key, value := range authParams(clientID) {
		query.Set(key, value.(string))
	}
	described := env.json(http.MethodGet, "/api/oauth/consent?"+query.Encode(), nil, "")
	if described.status != http.StatusOK {
		t.Fatalf("Expected 200, got %d %s", described.status, described.raw)
	}
	if name := described.body["client"].(map[string]any)["name"]; name != "Test Client" {
		t.Fatalf("Expected the client name, got %v", name)
	}
	if described.str("redirectHost") != "client.example.com" || described.str("scope") != "content:read content:write" {
		t.Fatalf("Unexpected description %s", described.raw)
	}

	// approving redirects back with a code, the state and the issuer
	body := authParams(clientID)
	body["approve"] = true
	decided := env.json(http.MethodPost, "/api/oauth/consent", body, env.userToken)
	redirect, _ := url.Parse(decided.str("redirectTo"))
	if !strings.HasPrefix(decided.str("redirectTo"), testRedirect+"?") {
		t.Fatalf("Expected a redirect to the client, got %q", decided.str("redirectTo"))
	}
	if redirect.Query().Get("state") != "xyz" || redirect.Query().Get("iss") != testIssuer {
		t.Fatalf("Expected state and iss in %q", decided.str("redirectTo"))
	}

	tokens := env.exchange(clientID, redirect.Query().Get("code"))
	if tokens.status != http.StatusOK {
		t.Fatalf("Expected tokens, got %d %s", tokens.status, tokens.raw)
	}
	if tokens.str("token_type") != "Bearer" || tokens.str("scope") != "content:read content:write" || tokens.body["expires_in"] != float64(3600) {
		t.Fatalf("Unexpected token response %s", tokens.raw)
	}
	if tokens.header.Get("Cache-Control") != "no-store" {
		t.Fatal("Expected the token response not to be stored")
	}

	info := env.introspect(tokens.str("access_token"))
	if info.body["active"] != true || info.str("sub") != env.user.Id || info.str("aud") != testResource ||
		info.str("client_id") != clientID || info.str("collection_name") != "users" || info.str("scope") != "content:read content:write" {
		t.Fatalf("Unexpected introspection %s", info.raw)
	}

	// a refresh token is not an access token
	if info := env.introspect(tokens.str("refresh_token")); info.body["active"] != false {
		t.Fatalf("Expected the refresh token to be inactive as an access token, got %s", info.raw)
	}
}

func TestTokensAreStoredHashed(t *testing.T) {
	env := newTestEnv(t, Config{})
	_, tokens := env.authorized()

	records, err := env.app.FindAllRecords(CollectionNameTokens)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("Expected a code, an access and a refresh token, got %d", len(records))
	}
	for _, record := range records {
		hash := record.GetString("hash")
		if hash == tokens.str("access_token") || hash == tokens.str("refresh_token") || len(hash) != 64 {
			t.Fatalf("Expected only a hash to be stored, got %q", hash)
		}
	}
}

func TestCodeIsBoundToItsRequest(t *testing.T) {
	scenarios := []struct {
		name   string
		change func(values url.Values)
		error  string
	}{
		{"wrong verifier", func(v url.Values) { v.Set("code_verifier", strings.Repeat("x", 43)) }, "invalid_grant"},
		{"missing verifier", func(v url.Values) { v.Del("code_verifier") }, "invalid_grant"},
		{"wrong redirect", func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:3000/callback") }, "invalid_grant"},
		{"wrong resource", func(v url.Values) { v.Set("resource", "https://other.example.com/mcp") }, "invalid_target"},
		{"unknown code", func(v url.Values) { v.Set("code", "oac_nope") }, "invalid_grant"},
		{"unknown grant type", func(v url.Values) { v.Set("grant_type", "password") }, "unsupported_grant_type"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			env := newTestEnv(t, Config{})
			clientID := env.registerTestClient(nil).str("client_id")
			values := url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {clientID},
				"code":          {env.approve(authParams(clientID))},
				"redirect_uri":  {testRedirect},
				"code_verifier": {testVerifier},
				"resource":      {testResource},
			}
			s.change(values)
			res := env.form("/api/oauth/token", values)
			if res.status != http.StatusBadRequest || res.str("error") != s.error {
				t.Fatalf("Expected %s, got %d %s", s.error, res.status, res.raw)
			}
		})
	}
}

func TestCodeOfAnotherClient(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID := env.registerTestClient(nil).str("client_id")
	other := env.registerTestClient(nil).str("client_id")

	res := env.exchange(other, env.approve(authParams(clientID)))
	if res.status != http.StatusBadRequest || res.str("error") != "invalid_grant" {
		t.Fatalf("Expected invalid_grant, got %d %s", res.status, res.raw)
	}
}

func TestCodeReplayRevokesTheGrant(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID := env.registerTestClient(nil).str("client_id")
	code := env.approve(authParams(clientID))

	tokens := env.exchange(clientID, code)
	if tokens.status != http.StatusOK {
		t.Fatalf("Expected tokens, got %d %s", tokens.status, tokens.raw)
	}
	if res := env.exchange(clientID, code); res.status != http.StatusBadRequest || res.str("error") != "invalid_grant" {
		t.Fatalf("Expected invalid_grant on replay, got %d %s", res.status, res.raw)
	}
	if info := env.introspect(tokens.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected the tokens of a replayed code to be revoked")
	}
}

func TestExpiredCode(t *testing.T) {
	env := newTestEnv(t, Config{CodeTTL: time.Millisecond})
	clientID := env.registerTestClient(nil).str("client_id")
	code := env.approve(authParams(clientID))
	time.Sleep(5 * time.Millisecond)

	if res := env.exchange(clientID, code); res.str("error") != "invalid_grant" {
		t.Fatalf("Expected invalid_grant, got %d %s", res.status, res.raw)
	}
}

func TestRefreshRotation(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID, tokens := env.authorized()

	refresh := func(token string) testResponse {
		return env.form("/api/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {clientID},
			"refresh_token": {token},
			"resource":      {testResource},
		})
	}

	rotated := refresh(tokens.str("refresh_token"))
	if rotated.status != http.StatusOK || rotated.str("refresh_token") == tokens.str("refresh_token") {
		t.Fatalf("Expected a new pair, got %d %s", rotated.status, rotated.raw)
	}
	if info := env.introspect(tokens.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected the previous access token to end with its pair")
	}
	if info := env.introspect(rotated.str("access_token")); info.body["active"] != true {
		t.Fatal("Expected the new access token to work")
	}

	// a retry right after is refused without punishing the client
	if res := refresh(tokens.str("refresh_token")); res.str("error") != "invalid_grant" {
		t.Fatalf("Expected invalid_grant, got %d %s", res.status, res.raw)
	}
	if info := env.introspect(rotated.str("access_token")); info.body["active"] != true {
		t.Fatal("Expected a retry within the grace window not to revoke the grant")
	}

	// later, the old token coming back means it was copied
	_, err := env.app.DB().NewQuery("UPDATE {{" + CollectionNameTokens + "}} SET used = {:used} WHERE used != ''").
		Bind(dbx.Params{"used": dateTime(time.Now().Add(-time.Hour)).String()}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	if res := refresh(tokens.str("refresh_token")); res.str("error") != "invalid_grant" {
		t.Fatalf("Expected invalid_grant, got %d %s", res.status, res.raw)
	}
	if info := env.introspect(rotated.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected a reused refresh token to revoke the grant")
	}
	if res := refresh(rotated.str("refresh_token")); res.str("error") != "invalid_grant" {
		t.Fatal("Expected the whole grant to be gone")
	}
}

func TestRefreshScopeAndClient(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID, tokens := env.authorized()
	other := env.registerTestClient(nil).str("client_id")

	res := env.form("/api/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {other}, "refresh_token": {tokens.str("refresh_token")},
	})
	if res.str("error") != "invalid_grant" {
		t.Fatalf("Expected another client's refresh token to be refused, got %s", res.raw)
	}

	res = env.form("/api/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tokens.str("refresh_token")}, "scope": {"admin"},
	})
	if res.str("error") != "invalid_scope" {
		t.Fatalf("Expected a wider scope to be refused, got %s", res.raw)
	}

	res = env.form("/api/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tokens.str("refresh_token")}, "scope": {"content:read"},
	})
	if res.status != http.StatusOK || res.str("scope") != "content:read" {
		t.Fatalf("Expected a narrowed scope, got %d %s", res.status, res.raw)
	}
}

func TestExpiredAccessToken(t *testing.T) {
	env := newTestEnv(t, Config{AccessTokenTTL: time.Millisecond})
	_, tokens := env.authorized()
	time.Sleep(5 * time.Millisecond)

	if info := env.introspect(tokens.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected an expired token to be inactive")
	}
}

func TestRevoke(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID, tokens := env.authorized()
	other := env.registerTestClient(nil).str("client_id")

	// another client cannot revoke it
	env.form("/api/oauth/revoke", url.Values{"client_id": {other}, "token": {tokens.str("refresh_token")}})
	if info := env.introspect(tokens.str("access_token")); info.body["active"] != true {
		t.Fatal("Expected another client's revocation to change nothing")
	}

	res := env.form("/api/oauth/revoke", url.Values{"client_id": {clientID}, "token": {tokens.str("refresh_token")}})
	if res.status != http.StatusOK {
		t.Fatalf("Expected 200, got %d %s", res.status, res.raw)
	}
	if info := env.introspect(tokens.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected revoking the refresh token to end the grant")
	}

	if res := env.form("/api/oauth/revoke", url.Values{"client_id": {clientID}, "token": {"unknown"}}); res.status != http.StatusOK {
		t.Fatalf("Expected an unknown token to be a 200, got %d", res.status)
	}
}

func TestConsentValidation(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID := env.registerTestClient(nil).str("client_id")

	describe := func(change func(params map[string]any)) testResponse {
		params := authParams(clientID)
		change(params)
		query := url.Values{}
		for key, value := range params {
			query.Set(key, value.(string))
		}
		return env.json(http.MethodGet, "/api/oauth/consent?"+query.Encode(), nil, "")
	}

	// nothing is sent to a client or redirect that cannot be trusted
	for name, change := range map[string]func(map[string]any){
		"unknown client":      func(p map[string]any) { p["client_id"] = "nope" },
		"unregistered":        func(p map[string]any) { p["redirect_uri"] = "https://evil.example.com/callback" },
		"redirect with extra": func(p map[string]any) { p["redirect_uri"] = testRedirect + "/extra" },
		"missing redirect":    func(p map[string]any) { p["redirect_uri"] = "" },
	} {
		res := describe(change)
		if res.status != http.StatusBadRequest || res.str("error") != "invalid_client" || res.str("redirectTo") != "" {
			t.Errorf("%s: expected invalid_client without a redirect, got %d %s", name, res.status, res.raw)
		}
	}

	// the rest is reported to the client
	for name, s := range map[string]struct {
		change func(map[string]any)
		error  string
	}{
		"implicit":      {func(p map[string]any) { p["response_type"] = "token" }, "unsupported_response_type"},
		"no pkce":       {func(p map[string]any) { p["code_challenge"] = "" }, "invalid_request"},
		"plain pkce":    {func(p map[string]any) { p["code_challenge_method"] = "plain" }, "invalid_request"},
		"bad scope":     {func(p map[string]any) { p["scope"] = "a\"b" }, "invalid_scope"},
		"bad resource":  {func(p map[string]any) { p["resource"] = "https://app.example.com/mcp#frag" }, "invalid_target"},
		"http resource": {func(p map[string]any) { p["resource"] = "http://app.example.com/mcp" }, "invalid_target"},
	} {
		res := describe(s.change)
		redirect, _ := url.Parse(res.str("redirectTo"))
		if res.status != http.StatusBadRequest || res.str("error") != s.error ||
			!strings.HasPrefix(res.str("redirectTo"), testRedirect+"?") ||
			redirect.Query().Get("error") != s.error || redirect.Query().Get("state") != "xyz" || redirect.Query().Get("iss") != testIssuer {
			t.Errorf("%s: expected %s by redirect, got %d %s", name, s.error, res.status, res.raw)
		}
	}

	// a loopback redirect may use any port
	if res := describe(func(p map[string]any) { p["redirect_uri"] = "http://127.0.0.1:51234/callback" }); res.status != http.StatusOK {
		t.Errorf("Expected a loopback redirect on another port to be accepted, got %d %s", res.status, res.raw)
	}
	if res := describe(func(p map[string]any) { p["redirect_uri"] = "http://127.0.0.1:51234/other" }); res.status != http.StatusBadRequest {
		t.Errorf("Expected a loopback redirect on another path to be refused, got %d", res.status)
	}
}

func TestConsentDecision(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID := env.registerTestClient(nil).str("client_id")

	// only a signed-in user decides, and never a superuser
	body := authParams(clientID)
	body["approve"] = true
	if res := env.json(http.MethodPost, "/api/oauth/consent", body, ""); res.status != http.StatusUnauthorized {
		t.Fatalf("Expected 401, got %d %s", res.status, res.raw)
	}
	if res := env.json(http.MethodPost, "/api/oauth/consent", body, env.superuserToken); res.status != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d %s", res.status, res.raw)
	}

	// declining reports access_denied and issues nothing
	body["approve"] = false
	res := env.json(http.MethodPost, "/api/oauth/consent", body, env.userToken)
	redirect, _ := url.Parse(res.str("redirectTo"))
	if redirect.Query().Get("error") != "access_denied" || redirect.Query().Get("code") != "" {
		t.Fatalf("Expected access_denied, got %s", res.raw)
	}
	if records, _ := env.app.FindAllRecords(CollectionNameTokens); len(records) != 0 {
		t.Fatal("Expected no code after declining")
	}

	// the page may grant less than was asked, and name the issuer it serves
	body["approve"] = true
	body["granted_scope"] = "content:read"
	body["issuer"] = "https://other.example.com/"
	res = env.json(http.MethodPost, "/api/oauth/consent", body, env.userToken)
	redirect, _ = url.Parse(res.str("redirectTo"))
	if redirect.Query().Get("iss") != "https://other.example.com" {
		t.Fatalf("Expected the given issuer, got %s", res.raw)
	}
	tokens := env.exchange(clientID, redirect.Query().Get("code"))
	if tokens.str("scope") != "content:read" {
		t.Fatalf("Expected the granted scope, got %s", tokens.raw)
	}
}

func TestApprovingAgainReplacesTheGrant(t *testing.T) {
	env := newTestEnv(t, Config{})
	clientID, first := env.authorized()

	second := env.exchange(clientID, env.approve(authParams(clientID)))
	if second.status != http.StatusOK {
		t.Fatalf("Expected tokens, got %d %s", second.status, second.raw)
	}
	if info := env.introspect(first.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected the first grant to be replaced")
	}
	if grants, _ := env.app.FindAllRecords(CollectionNameGrants); len(grants) != 1 {
		t.Fatalf("Expected one grant, got %d", len(grants))
	}
}

func TestRegistrationValidation(t *testing.T) {
	env := newTestEnv(t, Config{})

	for name, s := range map[string]struct {
		body  map[string]any
		error string
	}{
		"no redirects":      {map[string]any{"client_name": "x"}, "invalid_redirect_uri"},
		"http redirect":     {map[string]any{"redirect_uris": []string{"http://example.com/cb"}}, "invalid_redirect_uri"},
		"script redirect":   {map[string]any{"redirect_uris": []string{"javascript:alert(1)"}}, "invalid_redirect_uri"},
		"fragment redirect": {map[string]any{"redirect_uris": []string{"https://example.com/cb#x"}}, "invalid_redirect_uri"},
		"implicit grant":    {map[string]any{"redirect_uris": []string{testRedirect}, "grant_types": []string{"implicit"}}, "invalid_client_metadata"},
		"jwt auth":          {map[string]any{"redirect_uris": []string{testRedirect}, "token_endpoint_auth_method": "private_key_jwt"}, "invalid_client_metadata"},
	} {
		res := env.json(http.MethodPost, "/api/oauth/register", s.body, "")
		if res.status != http.StatusBadRequest || res.str("error") != s.error {
			t.Errorf("%s: expected %s, got %d %s", name, s.error, res.status, res.raw)
		}
	}

	// a native app's own scheme is a valid redirect
	res := env.json(http.MethodPost, "/api/oauth/register", map[string]any{"redirect_uris": []string{"com.example.app:/callback"}}, "")
	if res.status != http.StatusCreated {
		t.Fatalf("Expected a private-use scheme to be accepted, got %d %s", res.status, res.raw)
	}
}

func TestRegistrationRateLimit(t *testing.T) {
	env := newTestEnv(t, Config{})
	for i := 0; i < 20; i++ {
		env.registerTestClient(nil)
	}
	res := env.json(http.MethodPost, "/api/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}}, "")
	if res.status != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", res.status)
	}
}

func TestConfidentialClient(t *testing.T) {
	env := newTestEnv(t, Config{})
	registered := env.registerTestClient(map[string]any{"token_endpoint_auth_method": "client_secret_post"})
	clientID, secret := registered.str("client_id"), registered.str("client_secret")
	if secret == "" {
		t.Fatal("Expected a client secret")
	}

	values := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {env.approve(authParams(clientID))},
		"redirect_uri":  {testRedirect},
		"code_verifier": {testVerifier},
	}
	res := env.form("/api/oauth/token", values)
	if res.status != http.StatusUnauthorized || res.str("error") != "invalid_client" {
		t.Fatalf("Expected invalid_client without the secret, got %d %s", res.status, res.raw)
	}
	if res.header.Get("WWW-Authenticate") != "" {
		t.Fatal("Expected no Basic challenge for a client that did not try Basic")
	}
	values.Set("client_secret", "wrong")
	if res := env.form("/api/oauth/token", values); res.status != http.StatusUnauthorized {
		t.Fatalf("Expected invalid_client with a wrong secret, got %d %s", res.status, res.raw)
	}

	// HTTP Basic works as well as the form
	values.Del("client_secret")
	values.Del("client_id")
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong")
	if res := env.send(req); res.status != http.StatusUnauthorized || res.header.Get("WWW-Authenticate") == "" {
		t.Fatalf("Expected a Basic challenge for a wrong Basic secret, got %d %s", res.status, res.raw)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	if res := env.send(req); res.status != http.StatusOK {
		t.Fatalf("Expected tokens with Basic auth, got %d %s", res.status, res.raw)
	}
}

func TestIntrospectRequiresSuperuser(t *testing.T) {
	env := newTestEnv(t, Config{})
	_, tokens := env.authorized()

	body := map[string]string{"token": tokens.str("access_token")}
	if res := env.json(http.MethodPost, "/api/oauth/introspect", body, ""); res.status != http.StatusUnauthorized {
		t.Fatalf("Expected 401, got %d", res.status)
	}
	if res := env.json(http.MethodPost, "/api/oauth/introspect", body, env.userToken); res.status != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", res.status)
	}
}

func TestAccessTokenIsNotAPocketBaseToken(t *testing.T) {
	env := newTestEnv(t, Config{})
	_, tokens := env.authorized()

	// an OAuth token is scoped, so it must not open the regular API
	res := env.json(http.MethodGet, "/api/oauth/grants", nil, tokens.str("access_token"))
	if res.status != http.StatusUnauthorized {
		t.Fatalf("Expected 401, got %d %s", res.status, res.raw)
	}
}

func TestGrants(t *testing.T) {
	env := newTestEnv(t, Config{})
	_, tokens := env.authorized()

	list := env.json(http.MethodGet, "/api/oauth/grants", nil, env.userToken)
	items, _ := list.body["items"].([]any)
	if list.status != http.StatusOK || len(items) != 1 {
		t.Fatalf("Expected one grant, got %d %s", list.status, list.raw)
	}
	grant := items[0].(map[string]any)
	if grant["client"].(map[string]any)["name"] != "Test Client" || grant["scope"] != "content:read content:write" {
		t.Fatalf("Unexpected grant %v", grant)
	}

	// someone else cannot see or revoke it
	users, _ := env.app.FindCollectionByNameOrId("users")
	other := core.NewRecord(users)
	other.SetEmail("someone-else@example.com")
	other.SetPassword("1234567890")
	if err := env.app.Save(other); err != nil {
		t.Fatal(err)
	}
	otherToken, _ := other.NewAuthToken()
	if list := env.json(http.MethodGet, "/api/oauth/grants", nil, otherToken); len(list.body["items"].([]any)) != 0 {
		t.Fatal("Expected no grants for another user")
	}
	path := "/api/oauth/grants/" + grant["id"].(string)
	if res := env.json(http.MethodDelete, path, nil, otherToken); res.status != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", res.status)
	}

	if res := env.json(http.MethodDelete, path, nil, env.userToken); res.status != http.StatusNoContent {
		t.Fatalf("Expected 204, got %d %s", res.status, res.raw)
	}
	if info := env.introspect(tokens.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected a revoked grant's token to be inactive")
	}
}

func TestDeletedUserLosesGrants(t *testing.T) {
	env := newTestEnv(t, Config{})
	_, tokens := env.authorized()

	if err := env.app.Delete(env.user); err != nil {
		t.Fatal(err)
	}
	if info := env.introspect(tokens.str("access_token")); info.body["active"] != false {
		t.Fatal("Expected a deleted user's token to be inactive")
	}
	if grants, _ := env.app.FindAllRecords(CollectionNameGrants); len(grants) != 0 {
		t.Fatal("Expected the grants to be deleted")
	}
	if tokens, _ := env.app.FindAllRecords(CollectionNameTokens, dbx.HashExp{"kind": kindAccess}); len(tokens) != 0 {
		t.Fatal("Expected the tokens to be deleted")
	}
}

func TestCleanup(t *testing.T) {
	env := newTestEnv(t, Config{})
	env.authorized()
	env.registerTestClient(nil) // never approved

	// nothing is due yet
	if err := env.plugin.cleanup(env.app, time.Now()); err != nil {
		t.Fatal(err)
	}
	if clients, _ := env.app.FindAllRecords(CollectionNameClients); len(clients) != 2 {
		t.Fatalf("Expected both clients to be kept, got %d", len(clients))
	}
	if grants, _ := env.app.FindAllRecords(CollectionNameGrants); len(grants) != 1 {
		t.Fatal("Expected the grant to be kept")
	}

	// two months on, everything has expired
	if err := env.plugin.cleanup(env.app, time.Now().Add(60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{CollectionNameTokens, CollectionNameGrants, CollectionNameClients} {
		if records, _ := env.app.FindAllRecords(name); len(records) != 0 {
			t.Errorf("Expected %s to be empty, got %d", name, len(records))
		}
	}
}

// metadataServer serves a Client ID Metadata Document and counts the fetches.
func metadataServer(t *testing.T, document func(clientID string) map[string]any) (*httptest.Server, *int) {
	t.Helper()
	fetches := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=600")
		_ = json.NewEncoder(w).Encode(document(server.URL + r.URL.Path))
	}))
	t.Cleanup(server.Close)
	return server, &fetches
}

func TestClientIDMetadataDocument(t *testing.T) {
	server, fetches := metadataServer(t, func(clientID string) map[string]any {
		return map[string]any{
			"client_id":                  clientID,
			"client_name":                "Document Client",
			"client_uri":                 "https://client.example.com",
			"redirect_uris":              []string{testRedirect},
			"token_endpoint_auth_method": "none",
		}
	})
	env := newTestEnv(t, Config{HTTPClient: server.Client()})
	clientID := server.URL + "/oauth/client.json"

	tokens := env.exchange(clientID, env.approve(authParams(clientID)))
	if tokens.status != http.StatusOK {
		t.Fatalf("Expected tokens, got %d %s", tokens.status, tokens.raw)
	}
	if info := env.introspect(tokens.str("access_token")); info.str("client_id") != clientID {
		t.Fatalf("Unexpected introspection %s", info.raw)
	}
	if *fetches != 1 {
		t.Fatalf("Expected the document to be fetched once and then cached, got %d", *fetches)
	}

	list := env.json(http.MethodGet, "/api/oauth/grants", nil, env.userToken)
	client := list.body["items"].([]any)[0].(map[string]any)["client"].(map[string]any)
	if client["name"] != "Document Client" || client["uri"] != "https://client.example.com" {
		t.Fatalf("Unexpected client %v", client)
	}

	// once it is no longer fresh it is fetched again
	_, err := env.app.DB().NewQuery("UPDATE {{" + CollectionNameClients + "}} SET freshUntil = {:past}").
		Bind(dbx.Params{"past": dateTime(time.Now().Add(-time.Minute)).String()}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	env.approve(authParams(clientID))
	if *fetches != 2 {
		t.Fatalf("Expected a stale document to be fetched again, got %d", *fetches)
	}

	// and a copy that cannot be refreshed keeps working for a while
	server.Close()
	_, err = env.app.DB().NewQuery("UPDATE {{" + CollectionNameClients + "}} SET freshUntil = {:past}").
		Bind(dbx.Params{"past": dateTime(time.Now().Add(-time.Minute)).String()}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	env.approve(authParams(clientID))
}

func TestInvalidMetadataDocuments(t *testing.T) {
	for name, document := range map[string]func(clientID string) map[string]any{
		"another client_id": func(string) map[string]any {
			return map[string]any{"client_id": "https://other.example.com/client.json", "client_name": "x", "redirect_uris": []string{testRedirect}}
		},
		"no name": func(id string) map[string]any {
			return map[string]any{"client_id": id, "redirect_uris": []string{testRedirect}}
		},
		"no redirects": func(id string) map[string]any {
			return map[string]any{"client_id": id, "client_name": "x"}
		},
		"with a secret": func(id string) map[string]any {
			return map[string]any{"client_id": id, "client_name": "x", "redirect_uris": []string{testRedirect}, "token_endpoint_auth_method": "client_secret_post"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := metadataServer(t, document)
			env := newTestEnv(t, Config{HTTPClient: server.Client()})

			body := authParams(server.URL + "/client.json")
			body["approve"] = true
			res := env.json(http.MethodPost, "/api/oauth/consent", body, env.userToken)
			if res.status != http.StatusBadRequest || res.str("error") != "invalid_client" {
				t.Fatalf("Expected invalid_client, got %d %s", res.status, res.raw)
			}
		})
	}
}

func TestMetadataURLRules(t *testing.T) {
	for raw, valid := range map[string]bool{
		"https://client.example.com/client.json":      true,
		"https://client.example.com/a/b":              true,
		"https://client.example.com":                  false,
		"https://client.example.com/":                 false,
		"https://user:pass@client.example.com/client": false,
		"https://client.example.com/client#frag":      false,
		"https://client.example.com/a/../client":      false,
		"http://client.example.com/client.json":       false,
	} {
		if _, err := validateMetadataURL(raw); (err == nil) != valid {
			t.Errorf("Expected %q valid=%v, got %v", raw, valid, err)
		}
	}
}

// The default client must not be a way to reach this machine or its network.
func TestMetadataFetchRefusesPrivateAddresses(t *testing.T) {
	server, fetches := metadataServer(t, func(id string) map[string]any {
		return map[string]any{"client_id": id, "client_name": "x", "redirect_uris": []string{testRedirect}}
	})
	env := newTestEnv(t, Config{})

	body := authParams(server.URL + "/client.json") // https://127.0.0.1:port
	body["approve"] = true
	res := env.json(http.MethodPost, "/api/oauth/consent", body, env.userToken)
	if res.status != http.StatusBadRequest || res.str("error") != "invalid_client" {
		t.Fatalf("Expected invalid_client, got %d %s", res.status, res.raw)
	}
	if *fetches != 0 {
		t.Fatal("Expected no request to reach a loopback address")
	}

	for ip, public := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false, "fc00::1": false, "fe80::1": false,
		"::ffff:127.0.0.1": false, "::ffff:10.0.0.1": false,
	} {
		if isPublicIP(net.ParseIP(ip)) != public {
			t.Errorf("Expected %s public=%v", ip, public)
		}
	}
}

func TestFreshFor(t *testing.T) {
	for header, expected := range map[string]time.Duration{
		"":                      metadataDefaultFresh,
		"max-age=600":           10 * time.Minute,
		"public, max-age=10":    metadataMinFresh,
		"max-age=99999999":      metadataMaxFresh,
		"no-store":              metadataMinFresh,
		"private, max-age=7200": 2 * time.Hour,
	} {
		if got := freshFor(http.Header{"Cache-Control": {header}}); got != expected {
			t.Errorf("Expected %q to be fresh for %v, got %v", header, expected, got)
		}
	}
}
