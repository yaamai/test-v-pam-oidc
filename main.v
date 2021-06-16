module main

import json
import net.http
import net.urllib
import crypto.rand

struct OIDCConfig {
    issuer string
    authorization_endpoint string
    token_endpoint string
    jwks_uri string
}

struct OIDCContext {
    config OIDCConfig
    client_id string
    client_secret string
    redirect_uri string
    state string
    nonce string
}

struct OIDCTokenResponse {
    context OIDCContext
    access_token string
    expires_in int
    id_token string
}

fn (c OIDCConfig) new_oidc_context(client_id string, client_secret string, redirect_uri string) ?OIDCContext {
    return OIDCContext {
        config: c,
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        state: rand.read(8)?.hex(),
        nonce: rand.read(8)?.hex(),
    }
}

fn (c OIDCContext) get_authorize_url(scope []string, response_type []string) ?string {
    mut auth_url := urllib.parse(c.config.authorization_endpoint)?
    mut auth_params := urllib.new_values()
    auth_params.set("client_id", c.client_id)
    auth_params.set("redirect_uri", c.redirect_uri)
    auth_params.set("scope", scope.join(" "))
    auth_params.set("response_type", response_type.join(" "))
    auth_params.set("state", c.state)
    auth_url.raw_query = auth_params.encode()
    return auth_url.str()
}

fn (c OIDCContext) get_token_by_code(code string) ?OIDCTokenResponse {
    token_req := map{
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": c.redirect_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
    }
    resp := http.post_form(oidc_token_url, token_req)?
    return json.decode(OIDCTokenResponse, resp.text)
}

fn pam_sm_authenticate(mut p PAM, flags int, args map[string]string) ?int {
    config_data := http.get_text(args["oidc_config_url"])
    config := json.decode(OIDCConfig, config_data)?
    ctx := config.new_oidc_context(args["client_id"], args["client_secret"], args["redirect_uri"])?

    auth_url := ctx.get_authorize_url(args["scope"].split(","), args["response_type"].split(","))?
    p.prompt(C.PAM_TEXT_INFO, "Authorize URL: ${auth_url}")?

    // user := p.get_user("")?
    code := p.get_authtok("Code: ")?
    token := ctx.get_token_by_code(code)?

    println("${token}")
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
