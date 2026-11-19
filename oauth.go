// Package oauth turns PocketBase into an OAuth 2.1 authorization server, so
// other applications can act for the users of an auth collection with a
// scoped, revocable token instead of the user's own.
//
// It implements the profile the Model Context Protocol asks of an
// authorization server: the authorization code grant with PKCE (S256),
// refresh token rotation, resource indicators (RFC 8707), server metadata
// (RFC 8414), the iss response parameter (RFC 9207), Client ID Metadata
// Documents and dynamic client registration (RFC 7591).
//
// Example:
//
//	oauth.MustRegister(app, oauth.Config{})
//
// PocketBase has no browser session, so the page where a person signs in and
// approves a client belongs to the app in front of it. That page (the
// authorization endpoint, {issuer}/oauth/authorize by default) passes the
// query it was opened with to the consent endpoints below:
//
//	GET  /api/oauth/consent   the validated request and the client to show
//	POST /api/oauth/consent   the signed-in user's decision → {redirectTo}
//
// Everything a client talks to is served here:
//
//	GET  /.well-known/oauth-authorization-server
//	POST /api/oauth/register    dynamic client registration
//	POST /api/oauth/token       authorization_code and refresh_token grants
//	POST /api/oauth/revoke      RFC 7009
//
// A resource server checks a token with a superuser call, and users manage
// what they have approved:
//
//	POST   /api/oauth/introspect   RFC 7662 (superusers only)
//	GET    /api/oauth/grants       the signed-in user's approved clients
//	DELETE /api/oauth/grants/{id}
package oauth

import (
	"net/http"
	"strings"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

// Config defines the config options of the oauth plugin.
type Config struct {
	// Issuer is the authorization server's identifier: the public origin
	// clients reach it on, without a trailing slash (default to the
	// Application URL setting).
	Issuer string

	// AuthorizePath is where, under the issuer, the app serves the page that
	// signs the person in and asks for their consent
	// (default to "/oauth/authorize").
	AuthorizePath string

	// AccessTokenTTL is how long an access token is valid (default to 1h).
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is how long a refresh token is valid. Each use issues
	// a new one, so a client in use never expires (default to 30 days).
	RefreshTokenTTL time.Duration

	// CodeTTL is how long an authorization code is valid (default to 5m).
	CodeTTL time.Duration

	// DisableDynamicRegistration turns POST /api/oauth/register off, leaving
	// Client ID Metadata Documents as the only way in for a new client.
	DisableDynamicRegistration bool

	// HTTPClient fetches Client ID Metadata Documents (default to a client
	// that only connects to public addresses, doesn't follow redirects and
	// times out after 5s).
	HTTPClient *http.Client
}

type plugin struct {
	app     core.App
	config  Config
	limiter *limiter
}

// MustRegister registers the oauth plugin in the provided app instance
// and panics if it fails.
func MustRegister(app core.App, config Config) {
	if err := Register(app, config); err != nil {
		panic(err)
	}
}

// Register registers the oauth plugin in the provided app instance.
func Register(app core.App, config Config) error {
	_, err := register(app, config)
	return err
}

func register(app core.App, config Config) (*plugin, error) {
	config.Issuer = strings.TrimRight(config.Issuer, "/")
	if config.AuthorizePath == "" {
		config.AuthorizePath = "/oauth/authorize"
	}
	if config.AccessTokenTTL <= 0 {
		config.AccessTokenTTL = time.Hour
	}
	if config.RefreshTokenTTL <= 0 {
		config.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if config.CodeTTL <= 0 {
		config.CodeTTL = 5 * time.Minute
	}
	if config.HTTPClient == nil {
		config.HTTPClient = publicHTTPClient()
	}

	p := &plugin{app: app, config: config, limiter: newLimiter()}

	registerMigrations()

	// the system migrations are applied on bootstrap so apply them manually
	// in case the plugin is registered after that (eg. in tests)
	if app.IsBootstrapped() {
		if err := app.RunSystemMigrations(); err != nil {
			return nil, err
		}
	}

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		p.bindRoutes(se)
		return se.Next()
	})

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		e.App.Cron().Add("__oauthCleanup__", "17 * * * *", func() {
			if err := p.cleanup(e.App, time.Now()); err != nil {
				e.App.Logger().Warn("Failed to clean up OAuth data", "error", err)
			}
			p.limiter.prune(time.Now())
		})
		return nil
	})

	// what a deleted user or collection approved goes with it
	app.OnRecordAfterDeleteSuccess().BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Collection().IsAuth() {
			if err := deleteGrantsWhere(e.App, dbx.HashExp{"recordRef": e.Record.Id}); err != nil {
				e.App.Logger().Warn("Failed to delete the OAuth grants of a deleted record", "error", err)
			}
		}
		return e.Next()
	})
	app.OnCollectionAfterDeleteSuccess().BindFunc(func(e *core.CollectionEvent) error {
		if e.Collection.IsAuth() {
			if err := deleteGrantsWhere(e.App, dbx.HashExp{"collectionRef": e.Collection.Id}); err != nil {
				e.App.Logger().Warn("Failed to delete the OAuth grants of a deleted collection", "error", err)
			}
		}
		return e.Next()
	})

	return p, nil
}

func (p *plugin) bindRoutes(se *core.ServeEvent) {
	se.Router.GET("/.well-known/oauth-authorization-server", p.metadata)

	api := se.Router.Group("/api/oauth")
	if !p.config.DisableDynamicRegistration {
		api.POST("/register", p.registerClient)
	}
	api.GET("/consent", p.describeConsent)
	api.POST("/consent", p.decideConsent).Bind(apis.RequireAuth())
	// a confidential client authenticates with HTTP Basic, which PocketBase
	// would otherwise refuse as an unknown auth token
	api.POST("/token", p.token).Unbind(apis.DefaultRejectUnknownTokenMiddlewareId)
	api.POST("/revoke", p.revoke).Unbind(apis.DefaultRejectUnknownTokenMiddlewareId)
	api.POST("/introspect", p.introspect).Bind(apis.RequireSuperuserAuth(), apis.SkipSuccessActivityLog())
	api.GET("/grants", p.listGrants).Bind(apis.RequireAuth())
	api.DELETE("/grants/{id}", p.deleteGrant).Bind(apis.RequireAuth())
}

// issuer returns the authorization server's identifier.
func (p *plugin) issuer(app core.App) string {
	if p.config.Issuer != "" {
		return p.config.Issuer
	}
	return strings.TrimRight(app.Settings().Meta.AppURL, "/")
}

// metadata serves the authorization server metadata (RFC 8414).
func (p *plugin) metadata(e *core.RequestEvent) error {
	issuer := p.issuer(e.App)
	doc := map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + p.config.AuthorizePath,
		"token_endpoint":                                 issuer + "/api/oauth/token",
		"revocation_endpoint":                            issuer + "/api/oauth/revoke",
		"introspection_endpoint":                         issuer + "/api/oauth/introspect",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{authNone, authSecretPost, authSecretBasic},
		"revocation_endpoint_auth_methods_supported":     []string{authNone, authSecretPost, authSecretBasic},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	}
	if !p.config.DisableDynamicRegistration {
		doc["registration_endpoint"] = issuer + "/api/oauth/register"
	}
	e.Response.Header().Set("Cache-Control", "public, max-age=300")
	return e.JSON(http.StatusOK, doc)
}

// oauthError writes an error the way OAuth clients read it (RFC 6749 5.2),
// which is not PocketBase's own error shape.
func oauthError(e *core.RequestEvent, status int, code string, description string) error {
	e.Response.Header().Set("Cache-Control", "no-store")
	// only for a client that tried HTTP Basic (RFC 6749 5.2): a browser shown
	// the challenge unasked would put up its own password prompt
	if status == http.StatusUnauthorized && e.Request.Header.Get("Authorization") != "" {
		e.Response.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	}
	return e.JSON(status, map[string]string{"error": code, "error_description": description})
}
