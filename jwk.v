import encoding.base64
import crypto.sha256

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#flag -lssl -lcrypto
fn C.BN_bin2bn(&char, int, voidptr) voidptr
fn C.RSA_new() voidptr
fn C.RSA_set0_key(voidptr, voidptr, voidptr, voidptr) voidptr
fn C.RSA_verify(typ int, m &char, m_len size_t, sig &char, sig_len size_t, rsa voidptr) int

fn C.ERR_get_error() u32
fn C.ERR_error_string(u32, charptr) charptr
fn C.RSA_size(voidptr) int


fn main() {
    // n := "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw"
    n := "vAhVD1m54-qIyW4Gd1JNKax-TmbVG0EsrykF6BJlZmmhZdxo5XkhsL_PEsf7OIzXxacVeT5EerLD5H02oL-gZ09q2l7JgryaB1lzTVvlriWf4E4Hd-oXzh6sH9cir1okW8cseXPuIbloQ27TUZuUAqhBPTXAcM01xF5pd2hLigGsYZvbrRZyqz0haVYCilI-Agr60kObvrJVdib-AN-rqCSdbunylRlvAkZiyj5Eq6znpZ4WEDhLbUTvKfQXt-86W6Gw7fL2YM6vfLgh1P7CTF8GqT-LA-s1GGyJ8JyJ2GiyBouES0sdCRvwav4BtMuABCc8rDNZKn4SF9-seiUNIAcA4vkbjoNBVgMAh6KO3V6kYw7_6Uan539e2sXCzjtidrEfO3U0Sct3HE8_so2SSaOzBQiOYPl7lfHs-kgbFbR6xkJl9r9pALkc0ZFcMaN3epNhFKJAfZEwJssU2Nn-6LFA_xp0M10haBehoJiN_sfkT3gX7GMn3Kx16xBtQds71ceLs67vrpulP9KgVj36L6xw4zwHg4beNF_bHHd7EMbvBi3cL1KcsQ9r869LOx0nXKM-HPnJzoaSsfVnhx2IbuCNSLghm0c_TLLSc2U4hFfyANnIsD5SQpEUj1ckZmk2hDnRnPfrfJZjbOjpMdrGUoLmhaevPrYLDsK40qAtiOU"
    e := "AQAB"

    nb := base64.url_decode_str(n)
    eb := base64.url_decode_str(e)

    mod := C.BN_bin2bn(nb.str, nb.len, 0)
    exp := C.BN_bin2bn(eb.str, eb.len, 0)
    rsa := C.RSA_new()
    rc1 := C.RSA_set0_key(rsa, mod, exp, 0)
    println("rc1: ${rc1}")

    jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzoyMThmYWI5ZS1mOGFlLTQ0MDgtYWU1My0zMTNlZWFhZDA1Y2EiLCJ0eXAiOiJKV1QifQ.eyJhdF9oYXNoIjoiZ1NFNDU1Q3pyR2ZtUkdyYkdHR1ljZyIsImF1ZCI6WyJ0ZXN0Il0sImF1dGhfdGltZSI6MTYyMzc4NzM0MSwiZXhwIjoxNjIzNzkwOTUyLCJpYXQiOjE2MjM3ODczNTIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDQ0NC8iLCJqdGkiOiJhNDE1NWQyYi04NWQwLTQ0ODktYjdhYS0yNDQ3YzVhZDhkNmUiLCJub25jZSI6IiIsInJhdCI6MTYyMzc4NzMzNCwic2lkIjoiNGU2YzU0Y2QtNjdkYi00NzhlLTk2Y2YtYTZiYmU5OTBiMTY4Iiwic3ViIjoiZm9vQGJhci5jb20ifQ.S8So6mSU_kmu3AtsjIdLOyXxEsFiCwqL8ma6PCP5rO5N5i62Vqrtonx_0slJnUbBDk4puAb3RgvfC1mdPNEA9qRqE4xq7Jzg2NwkgXtj9fVrPuveVfkfAOauJxiBPcpc0Q-vcTBwxHisEn_LbdIYpU4rDp1W3qRj9qm0RQKOGtgLMtl1I3UpyQLcRRqmj6clCKcvtSjYW6Lo2bHjJ4bwq7t-d6kZGWjXt1tvR7Bb27xNv_Y6chdGTeDFPSW0m61GvPgrOREmyQc4MkjDrMFoTdhzHDqVXRrEPqg156DtuHvR07DzmxdzrU4XGePn-h3_vRCLgH8PtEv2sZ8YKOIQeRV6ZvdNy0iFBz65t9jPNMVtvxII0YagckKfjKT7lAi2wu3W6LGaMwOqU81InSb82vfGj1q1H-_iuoTIRAHjDAPoT2C3N8VoM_3J6WACv4rQ3mIHak9_4SSXq0U2JAo9nKDrV62c-LUDPmfagNzUJ0C4WCDrbOXx9LsdyeohnGdffLSxn7XUuszNnJe7ByakykWqyQH92tKXIBIrCMLHy4fF3vplmDe2hHoz5NuvzLP26qOsGW2t7cRoQmEG8slTZDY_EJ6M2axLe6qQtIe5q5TK7veSDY89PY2BmrjYGaCrjjcArATyYdXoO8r1iKAyZ6XKqGbGE7kDsU_rlZTdk1U"

    jwt_elems := jwt.split(".")
    data := jwt_elems[0]+"."+jwt_elems[1]
    println(data)
    println(data.len)
    println(jwt.len)
    println(data.bytes()[0])
    println(sha256.hexhash(data))
    println(sha256.hexhash(""))
    data_sum := sha256.sum256(data.bytes())
    println(data_sum)
    sig := base64.url_decode_str(jwt_elems[2])
    println(sig.len)
    println(C.RSA_size(rsa))

    rc2 := C.RSA_verify(C.NID_sha256, data_sum.data, data_sum.len, sig.str, sig.len, rsa)
    err := C.ERR_get_error()
    println("rc2: ${rc2}")
    println("rc2: ${}")

    err_str := []byte{len: 1024}
    C.ERR_error_string(err, err_str.data)
    println(err_str.bytestr())
}
