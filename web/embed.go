// Package web provides embedded web assets for the Talon dashboard.
package web

import _ "embed"

//go:embed dashboard.html
var DashboardHTML string
