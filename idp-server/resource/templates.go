package resource

import (
	"embed"
	"html/template"
)

//go:embed static/*.html
var staticFiles embed.FS

var LoginPageTemplate = template.Must(template.ParseFS(staticFiles, "static/login.html"))
var LoginTOTPTemplate = template.Must(template.ParseFS(staticFiles, "static/login_totp.html"))
var ConsentPageTemplate = template.Must(template.ParseFS(staticFiles, "static/consent.html"))
var DevicePageTemplate = template.Must(template.ParseFS(staticFiles, "static/device.html"))
var TOTPSetupTemplate = template.Must(template.ParseFS(staticFiles, "static/totp_setup.html"))
var LogoutPageTemplate = template.Must(template.ParseFS(staticFiles, "static/logout.html"))
var RegisterPageTemplate = template.Must(template.ParseFS(staticFiles, "static/register.html"))
