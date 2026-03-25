package resource

import (
	"embed"
	"html/template"
)

//go:embed static/*.html
var staticFiles embed.FS

var LoginPageTemplate = template.Must(template.ParseFS(staticFiles, "static/login.html"))
var ConsentPageTemplate = template.Must(template.ParseFS(staticFiles, "static/consent.html"))
var LogoutPageTemplate = template.Must(template.ParseFS(staticFiles, "static/logout.html"))
