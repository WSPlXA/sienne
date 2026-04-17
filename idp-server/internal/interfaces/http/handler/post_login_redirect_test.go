package handler

import "testing"

func TestResolveBrowserPostLoginRedirect(t *testing.T) {
	tests := []struct {
		name             string
		returnTo         string
		upstreamRedirect string
		roleCode         string
		want             string
	}{
		{
			name:             "return_to_has_highest_priority",
			returnTo:         "/oauth2/authorize?client_id=demo",
			upstreamRedirect: "/admin",
			roleCode:         "support",
			want:             "/oauth2/authorize?client_id=demo",
		},
		{
			name:             "upstream_redirect_kept_when_present",
			returnTo:         "",
			upstreamRedirect: "/oauth2/authorize?client_id=demo",
			roleCode:         "support",
			want:             "/oauth2/authorize?client_id=demo",
		},
		{
			name:             "support_role_defaults_to_support_workbench",
			returnTo:         "",
			upstreamRedirect: "",
			roleCode:         "support",
			want:             "/admin/workbench/support",
		},
		{
			name:             "oauth_admin_role_defaults_to_oauth_workbench",
			returnTo:         "",
			upstreamRedirect: "",
			roleCode:         "oauth_admin",
			want:             "/admin/workbench/oauth",
		},
		{
			name:             "security_admin_role_defaults_to_security_workbench",
			returnTo:         "",
			upstreamRedirect: "",
			roleCode:         "security_admin",
			want:             "/admin/workbench/security",
		},
		{
			name:             "super_admin_role_defaults_to_admin_console",
			returnTo:         "",
			upstreamRedirect: "",
			roleCode:         "super_admin",
			want:             "/admin",
		},
		{
			name:             "end_user_role_defaults_to_root",
			returnTo:         "",
			upstreamRedirect: "",
			roleCode:         "end_user",
			want:             "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveBrowserPostLoginRedirect(tt.returnTo, tt.upstreamRedirect, tt.roleCode)
			if got != tt.want {
				t.Fatalf("resolveBrowserPostLoginRedirect() = %q, want %q", got, tt.want)
			}
		})
	}
}
