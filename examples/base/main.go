package main

import (
	"log"

	"ganigeorgiev.com/pocketbase/pocketbase"
	"github.com/velastack/pocketbase-oauth"
)

func main() {
	app := pocketbase.New()

	oauth.MustRegister(app, oauth.Config{})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
