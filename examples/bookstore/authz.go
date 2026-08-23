package main

import (
	_ "embed"

	authz "github.com/braveokafor/connectrpc-authz-go"
	authzcasbin "github.com/braveokafor/connectrpc-authz-go/casbin"
)

//go:embed policies/model.conf
var modelConf string

//go:embed policies/policy.csv
var policyCSV string

func newEnforcer() (authz.Enforcer, error) {
	return authzcasbin.NewFromString(modelConf, policyCSV, getSubjects)
}

func getSubjects(r *authz.Request) []string {
	if id, ok := r.Identity.(*Identity); ok && id != nil {
		return []string{id.Subject}
	}
	return nil
}
