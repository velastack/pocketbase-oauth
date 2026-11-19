package oauth

import (
	"net/http"
	"sync"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

// revokeGrant deletes a grant and every token issued under it.
func revokeGrant(app core.App, grantID string) error {
	if grantID == "" {
		return nil
	}
	if _, err := app.DB().Delete(CollectionNameTokens, dbx.HashExp{"grantRef": grantID}).Execute(); err != nil {
		return err
	}
	_, err := app.DB().Delete(CollectionNameGrants, dbx.HashExp{"id": grantID}).Execute()
	return err
}

// deleteGrantsWhere revokes every grant matching the expression.
func deleteGrantsWhere(app core.App, exp dbx.Expression) error {
	grants, err := app.FindAllRecords(CollectionNameGrants, exp)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if err := revokeGrant(app, grant.Id); err != nil {
			return err
		}
	}
	return nil
}

// listGrants returns the clients the signed-in user has approved.
func (p *plugin) listGrants(e *core.RequestEvent) error {
	grants, err := e.App.FindAllRecords(CollectionNameGrants, dbx.HashExp{
		"collectionRef": e.Auth.Collection().Id,
		"recordRef":     e.Auth.Id,
	})
	if err != nil {
		return err
	}

	items := make([]map[string]any, 0, len(grants))
	for _, grant := range grants {
		client := &Client{ID: grant.GetString("clientId")}
		if record, _ := e.App.FindFirstRecordByData(CollectionNameClients, "clientId", client.ID); record != nil {
			client = clientFromRecord(record)
		}
		items = append(items, map[string]any{
			"id":       grant.Id,
			"client":   clientView(client),
			"scope":    grant.GetString("scope"),
			"resource": grant.GetString("resource"),
			"created":  grant.GetDateTime("created"),
			"lastUsed": grant.GetDateTime("lastUsed"),
		})
	}
	return e.JSON(http.StatusOK, map[string]any{"items": items})
}

// deleteGrant revokes one of the signed-in user's grants.
func (p *plugin) deleteGrant(e *core.RequestEvent) error {
	grant, err := e.App.FindRecordById(CollectionNameGrants, e.Request.PathValue("id"))
	if err != nil ||
		grant.GetString("recordRef") != e.Auth.Id ||
		grant.GetString("collectionRef") != e.Auth.Collection().Id {
		return e.NotFoundError("", nil)
	}
	if err := revokeGrant(e.App, grant.Id); err != nil {
		return err
	}
	return e.NoContent(http.StatusNoContent)
}

// cleanup removes what has expired: tokens, the grants left without any, and
// the clients nobody approved.
func (p *plugin) cleanup(app core.App, now time.Time) error {
	nowStr := dateTime(now).String()

	if _, err := app.DB().Delete(CollectionNameTokens, dbx.NewExp("expires < {:now}", dbx.Params{"now": nowStr})).Execute(); err != nil {
		return err
	}

	// a grant's refresh token outlives everything else it has
	if _, err := app.DB().NewQuery(
		"DELETE FROM {{" + CollectionNameGrants + "}} WHERE id NOT IN (SELECT grantRef FROM {{" + CollectionNameTokens + "}})",
	).Execute(); err != nil {
		return err
	}

	_, err := app.DB().NewQuery(
		"DELETE FROM {{" + CollectionNameClients + "}} WHERE clientId NOT IN (SELECT clientId FROM {{" + CollectionNameGrants + "}}) AND " +
			"((source = 'dcr' AND created < {:registered}) OR (source = 'cimd' AND freshUntil < {:fetched}))",
	).Bind(dbx.Params{
		"registered": dateTime(now.Add(-30 * 24 * time.Hour)).String(),
		"fetched":    dateTime(now.Add(-metadataStaleFor)).String(),
	}).Execute()
	return err
}

// limiter is a small sliding-window rate limiter kept in memory.
type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter() *limiter {
	return &limiter{hits: map[string][]time.Time{}}
}

// allow records a hit for key and reports whether it is within max per window.
func (l *limiter) allow(key string, max int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	recent := l.hits[key][:0]
	for _, hit := range l.hits[key] {
		if now.Sub(hit) < window {
			recent = append(recent, hit)
		}
	}
	if len(recent) >= max {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	return true
}

// prune forgets the keys with no hit in the last day.
func (l *limiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for key, hits := range l.hits {
		if len(hits) == 0 || now.Sub(hits[len(hits)-1]) > 24*time.Hour {
			delete(l.hits, key)
		}
	}
}
