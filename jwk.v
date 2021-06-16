module main

import json
import net.http
import encoding.base64
import crypto.sha256

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#flag -lssl -lcrypto
fn C.BN_bin2bn(&char, int, voidptr) voidptr
fn C.RSA_new() voidptr
fn C.RSA_set0_key(voidptr, voidptr, voidptr, voidptr) int
fn C.RSA_verify(typ int, m &char, m_len size_t, sig &char, sig_len size_t, rsa voidptr) int

struct JWK {
    use string
    kty string
    kid string
    alg string
    n string
    e string
}

struct JWKSet {
    keys []JWK
}

fn parse_jwk_set(url string) ?JWKSet {
    data := http.get_text(oidc_token_url)
    return json.decode(JWKSet, data)
}

/*
TODO: follow ID Token validation spec
If the ID Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt the ID Token. If encryption was negotiated with the OP at Registration time and the ID Token is not encrypted, the RP SHOULD reject it.
The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by the Issuer.
The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the id_token_signed_response_alg parameter during Registration.
If the JWT alg Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512, the octets of the UTF-8 representation of the client_secret corresponding to the client_id contained in the aud (audience) Claim are used as the key to validate the signature. For MAC based algorithms, the behavior is unspecified if the aud is multi-valued or if an azp value is present that is different than the aud value.
The current time MUST be before the time represented by the exp Claim.
The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the nonce value for replay attacks. The precise method for detecting replay attacks is Client specific.
If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate. The meaning and processing of acr Claim Values is out of scope for this specification.
If the auth_time Claim was requested, either through a specific request for this Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication.
*/
fn load_rsa_key(n string, e string) ?voidptr {
    // load rsa key
    nb := base64.url_decode_str(n)
    eb := base64.url_decode_str(e)
    mod := C.BN_bin2bn(nb.str, nb.len, 0)
    exp := C.BN_bin2bn(eb.str, eb.len, 0)
    rsa := C.RSA_new()
    rc := C.RSA_set0_key(rsa, mod, exp, voidptr(0))
    if rc != 1 {
        return error('failed to load RSA key')
    }

    return rsa
}

fn rsa_sha256_verify(rsa voidptr, data []byte, sig []byte) ?bool {
    data_sum := sha256.sum256(data)
    rc := C.RSA_verify(C.NID_sha256, data_sum.data, data_sum.len, sig.data, sig.len, rsa)
    if rc != 1 {
        return error('failed to verify signature')
    }

    return true
}

fn (s JWKSet) verify(jwt string) ?bool {
    jwt_elems := jwt.split(".")

    rsa := load_rsa_key(s.keys[0].n, s.keys[1].e)?
    data := jwt_elems[0]+"."+jwt_elems[1]
    sig := base64.url_decode(jwt_elems[2])
    return rsa_sha256_verify(rsa, data.bytes(), sig)
}
