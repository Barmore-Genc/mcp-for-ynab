// Package ynab is the client for the YNAB REST API. client.gen.go is generated
// from YNAB's own OpenAPI document, which is vendored here as openapi.yaml so
// that regenerating is a local operation and a spec change shows up as a diff.
//
// Refresh the spec with:
//
//	curl -o internal/ynab/openapi.yaml https://api.ynab.com/papi/spec.yaml
//
// then `go generate ./...`.
package ynab

//go:generate go run ../../tools/openapi30 openapi.yaml openapi-3.0.yaml
//go:generate go tool oapi-codegen -config oapi-codegen.yaml openapi-3.0.yaml
