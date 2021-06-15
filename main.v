module main

import net.http
import net.urllib

fn pam_sm_authenticate(mut p PAM, flags int, args map[string]string) ?int {
    mut auth_url := urllib.parse(oidc_auth_url)?
    mut auth_params := urllib.new_values()
    auth_params.set("client_id", "test")
    auth_params.set("scope", "openid offline")
    auth_params.set("response_type", "code")
    auth_params.set("state", "abcdefgh")
    auth_url.raw_query = auth_params.encode()

    p.prompt(C.PAM_TEXT_INFO, "Authorize URL: ${auth_url}")?
    user := p.get_user("")?
    code := p.get_authtok("Code: ")?
    println("${user}, ${code}")

    token_req := map{
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "",
        "client_id": "test",
        "client_secret": "some-secret",
    }
    resp := http.post_form(oidc_token_url, token_req) or { 
        println(err)
        return 0
    }
    println("${resp}")
    return C.PAM_SUCCESS
}

fn pam_sm_setcred(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_SUCCESS }
fn pam_sm_acct_mgmt(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_IGNORE }
fn pam_sm_open_session(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_SUCCESS }
fn pam_sm_close_session(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_SUCCESS }
fn pam_sm_chauthtok(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_AUTHTOK_ERR }

const (
    oidc_auth_url = "http://localhost:4444/oauth2/auth"
    oidc_token_url = "http://localhost:4444/oauth2/token"
)

fn parse_pam_args(argc int, args &&C.cchar) map[string]string {
    mut result := map[string]string{}
    for idx := 0; idx < argc; idx++ {
        p := unsafe { args+idx }
        s := unsafe { cstring_to_vstring(&char(*p))}
        keyval := s.split_nth("=", 2)
        if keyval.len == 2 {
            result[keyval[0]] = keyval[1]
        } else if keyval.len == 1 {
            result[keyval[0]] = ""
        }
    }
    return result
}

