package oauth

import (
	"sync"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

const (
	// CollectionNameClients is the name of the system collection that stores
	// the registered clients and the fetched Client ID Metadata Documents.
	CollectionNameClients = "_oauthClients"

	// CollectionNameGrants is the name of the system collection that stores
	// what each user approved: one row per user, client and resource.
	CollectionNameGrants = "_oauthGrants"

	// CollectionNameTokens is the name of the system collection that stores
	// the hashes of the authorization codes, access and refresh tokens.
	CollectionNameTokens = "_oauthTokens"
)

var registerMigrationsOnce sync.Once

func registerMigrations() {
	registerMigrationsOnce.Do(func() {
		core.SystemMigrations.Register(migrateUp, migrateDown, "1792000000_oauth_init.go")
	})
}

func migrateUp(txApp core.App) error {
	clients := core.NewBaseCollection(CollectionNameClients)
	clients.System = true
	clients.Fields.Add(
		&core.TextField{Name: "clientId", System: true, Required: true, Max: 2048},
		// "dcr" (registered here) or "cimd" (a fetched metadata document)
		&core.TextField{Name: "source", System: true, Required: true},
		&core.TextField{Name: "secretHash", System: true, Hidden: true},
		&core.TextField{Name: "authMethod", System: true, Required: true},
		&core.TextField{Name: "name", System: true, Max: 200},
		&core.TextField{Name: "uri", System: true, Max: 2048},
		&core.TextField{Name: "logoUri", System: true, Max: 2048},
		&core.JSONField{Name: "redirectUris", System: true, MaxSize: 20000},
		// until when a fetched metadata document is used without asking again
		&core.DateField{Name: "freshUntil", System: true},
		&core.AutodateField{Name: "created", System: true, OnCreate: true},
		&core.AutodateField{Name: "updated", System: true, OnCreate: true, OnUpdate: true},
	)
	clients.AddIndex("idx_oauthClients_clientId", true, "clientId", "")
	if err := txApp.Save(clients); err != nil {
		return err
	}

	grants := core.NewBaseCollection(CollectionNameGrants)
	grants.System = true
	grants.Fields.Add(
		&core.TextField{Name: "clientId", System: true, Required: true, Max: 2048},
		&core.TextField{Name: "collectionRef", System: true, Required: true},
		&core.TextField{Name: "recordRef", System: true, Required: true},
		&core.TextField{Name: "scope", System: true, Max: 2000},
		&core.TextField{Name: "resource", System: true, Max: 2048},
		&core.DateField{Name: "lastUsed", System: true},
		&core.AutodateField{Name: "created", System: true, OnCreate: true},
		&core.AutodateField{Name: "updated", System: true, OnCreate: true, OnUpdate: true},
	)
	grants.AddIndex("idx_oauthGrants_recordRef", false, "recordRef", "")
	grants.AddIndex("idx_oauthGrants_clientId", false, "clientId", "")
	if err := txApp.Save(grants); err != nil {
		return err
	}

	tokens := core.NewBaseCollection(CollectionNameTokens)
	tokens.System = true
	tokens.Fields.Add(
		// sha256 of the token; the token itself is never stored
		&core.TextField{Name: "hash", System: true, Required: true, Hidden: true},
		// "code", "access" or "refresh"
		&core.TextField{Name: "kind", System: true, Required: true},
		&core.TextField{Name: "grantRef", System: true},
		&core.TextField{Name: "scope", System: true, Max: 2000},
		&core.DateField{Name: "expires", System: true, Required: true},
		// when a code was redeemed or a refresh token rotated: presenting
		// either again means it leaked, and revokes the grant
		&core.DateField{Name: "used", System: true},
		// what an authorization code is bound to until it is redeemed
		&core.JSONField{Name: "request", System: true, Hidden: true, MaxSize: 20000},
		&core.AutodateField{Name: "created", System: true, OnCreate: true},
	)
	tokens.AddIndex("idx_oauthTokens_hash", true, "hash", "")
	tokens.AddIndex("idx_oauthTokens_grantRef", false, "grantRef", "")
	tokens.AddIndex("idx_oauthTokens_expires", false, "expires", "")

	return txApp.Save(tokens)
}

func migrateDown(txApp core.App) error {
	for _, name := range []string{CollectionNameTokens, CollectionNameGrants, CollectionNameClients} {
		col, err := txApp.FindCollectionByNameOrId(name)
		if err != nil {
			continue
		}

		// system collections can't be deleted directly
		// (and the system flag change is not allowed by the collection validator)
		col.System = false
		if err := txApp.SaveNoValidate(col); err != nil {
			return err
		}
		if err := txApp.Delete(col); err != nil {
			return err
		}
	}

	return nil
}
