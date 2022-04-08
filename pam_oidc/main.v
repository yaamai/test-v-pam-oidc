module main

import os
import json
import time
import net.http
import net.urllib
import crypto.rand
import encoding.base64

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
    id_token_str string [json: "id_token"]
    id_token JWT
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
    auth_params.set("nonce", c.nonce)
    auth_url.raw_query = auth_params.encode()
    return auth_url.str()
}

struct JWT {
    header JWTHeader
    payload JWTPayload
}

struct JWTHeader {
    alg string
    kid string
    typ string
}
struct JWTPayload {
    aud []string
    exp int
    iat int
    iss string
    sub string
    nonce string
}

fn (c OIDCContext) validate_id_token(token OIDCTokenResponse) ?JWT {
    jwt_elems := token.id_token_str.split(".")
    header_str := base64.url_decode_str(jwt_elems[0])
    header := json.decode(JWTHeader, header_str)?
    payload_str := base64.url_decode_str(jwt_elems[1])
    payload := json.decode(JWTPayload, payload_str)?

    if payload.iss != c.config.issuer { return error('unknown issuer') }
    if payload.aud.len != 1 { return error('unexpected audience length (TODO?)') }
    if payload.aud[0] != c.client_id { return error('client_id not in audience') }

    jwk_set := parse_jwk_set(c.config.jwks_uri)?
    jwk_set.verify(jwt_elems[0], jwt_elems[1], jwt_elems[2])?

    if header.alg != "RS256" { return error('not supported alg') }
    now := time.now().unix_time()
    if payload.exp < now-15 { return error('id token expired') }
    // TODO: check iat if mathutil.abs(payload.iat-now) < 120 { return error('') }
    if payload.nonce != c.nonce { return error('invalid nonce value') }

    return JWT{header: header, payload: payload}
}

fn (c OIDCContext) get_token_by_code(code string) ?OIDCTokenResponse {
    token_req := {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": c.redirect_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
    }
    resp := http.post_form(c.config.token_endpoint, token_req)?
    if http.status_from_int(resp.status_code).is_error() {
        return error('failed to request token: ${resp.text}')
    }
    token := json.decode(OIDCTokenResponse, resp.text)?
    jwt := c.validate_id_token(token)?
    return OIDCTokenResponse{
        ...token,
        context: c,
        id_token: jwt,
    }
}

fn (c OIDCContext) get_token_by_url(url_str string) ?OIDCTokenResponse {
    url := urllib.parse(url_str)?
    query := url.query()

    if c.state != query.get('state') { return error('state value mismatch') }
    return c.get_token_by_code(query.get('code'))
}


fn pam_sm_authenticate(mut p PAM, flags int, args map[string]string) ?int {
    config_resp := http.get(args["oidc_config_url"])?
    config := json.decode(OIDCConfig, config_resp.text)?
    ctx := config.new_oidc_context(args["client_id"], args["client_secret"], args["redirect_uri"])?

    auth_url := ctx.get_authorize_url(args["scope"].split(","), args["response_type"].split(","))?
    p.prompt(C.PAM_TEXT_INFO, "Please open and sign-in \"${auth_url}\".")?

    url := p.get_authtok("Paste redirected URL: ")?
    // TODO: receive URL instead of code string
    token := ctx.get_token_by_url(url)?

    user := p.get_user("")?
    mapping_json := os.read_file(args["mapping"]) or { "{}" }
    mapping := json.decode(map[string]string, mapping_json)?
    authenticated_user := mapping[token.id_token.payload.sub] or { token.id_token.payload.sub }

    if authenticated_user == user {
        return C.PAM_SUCCESS
    }
    return C.PAM_AUTH_ERR
}

fn pam_sm_setcred(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_SUCCESS }
fn pam_sm_acct_mgmt(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_IGNORE }
fn pam_sm_open_session(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_SUCCESS }
fn pam_sm_close_session(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_SUCCESS }
fn pam_sm_chauthtok(mut p PAM, flags int, args map[string]string) ?int { return C.PAM_AUTHTOK_ERR }
