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
fn C.RSA_verify(typ int, m &char, m_len int, sig &char, sig_len int, rsa voidptr) int

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
    data := http.get_text(url)
    return json.decode(JWKSet, data)
}

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

fn (s JWKSet) get(kid string) ?JWK {
    for k in s.keys {
        if k.kid == kid {
            return k
        }
    }
    return error('specified kid not found in JWK set')
}

fn (s JWKSet) verify(header_str_ string, payload string, sig_str string) ?bool {
    header_str := base64.url_decode_str(header_str_)
    header := json.decode(JWTHeader, header_str)?
    if header.alg != "RS256" { return error('not supported alg') }

    key := s.get(header.kid)?
    rsa := load_rsa_key(key.n, key.e)?
    data := "${header_str_}.${payload}"
    sig := base64.url_decode(sig_str)
    return rsa_sha256_verify(rsa, data.bytes(), sig)
}
