import os


#include <security/pam_modules.h>
#include "types.h"
fn C.pam_get_user(handle &C.pam_handle_t, user &&C.cchar, prompt &C.cchar) int
fn C.pam_get_authtok(handle &C.pam_handle_t, item int, token &&C.cchar, prompt &C.cchar) int
fn C.pam_get_item(handle &C.pam_handle_t, item_type int, item &voidptr) int
fn C.pam_prompt(handle &C.pam_handle_t, style int, resp &&char, fmt &C.cchar) int

struct Pam {
    handle &C.pam_handle_t
}

fn (mut p Pam) get_user(prompt string) ?string {
    user_ptr := &C.cchar(0)
    rc := C.pam_get_user(handle, &user_ptr, prompt.str)
    if rc != 0 {
        return error('')
    }
    return unsafe { cstring_to_vstring(&char(user_ptr)) }
}

fn (mut p Pam) get_authtok(prompt string) ?string {
    out := &C.cchar(0)
    p := if prompt == "" { 0 } else { prompt.str }
    rc := C.pam_get_user(handle, &out, p)
    if rc != 0 {
        return error('')
    }
    return unsafe { cstring_to_vstring(&char(out)) }
}

fn (mut p Pam) prompt(style int, fmt string) ?string {
}


[export: 'pam_sm_authenticate']
fn pam_sm_authenticate(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    pam := Pam{handle: handle}
    user := pam.get_user("") or { return 0 }
    token := pam.get_authtok("")

    println("pam_sm_authenticate")
    os.write_file("/tmp/auth", "pam_sm_authenticate") or { return 0 }

    user_ptr := &C.cchar(0)
    prompt := "aaaaa"
    rc := C.pam_get_user(handle, &user_ptr, prompt.str)
    user := unsafe { cstring_to_vstring(&char(user_ptr)) }
    println("test ${rc} ${user}")

    resp_ptr := &char(0)
    pr := "testestse"
    rc3 := C.pam_prompt(handle, C.PAM_TEXT_INFO, &resp_ptr, pr.str)
    println(rc3)

    pass_ptr := &C.cchar(0)
    rc2 := C.pam_get_authtok(handle, C.PAM_AUTHTOK, &pass_ptr, 0)
    pass := unsafe { cstring_to_vstring(&char(pass_ptr)) }
    println("test ${rc2} ${pass}")
    return C.PAM_SUCCESS
}

[export: 'pam_sm_setcred']
fn pam_sm_setcred(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    println("pam_sm_setcred")
    os.write_file("/tmp/a", "pam_sm_setcred") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_acct_mgmt']
fn pam_sm_acct_mgmt(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    println("pam_sm_acct_mgmt")
    os.write_file("/tmp/a", "pam_sm_acct_mgmt") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_open_session']
fn pam_sm_open_session(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    println("pam_sm_open_session")
    os.write_file("/tmp/a", "pam_sm_open_session") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_close_session']
fn pam_sm_close_session(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    println("pam_sm_close_session")
    os.write_file("/tmp/a", "pam_sm_close_session") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_chauthtok']
fn pam_sm_chauthtok(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    println("pam_sm_chauthtok")
    os.write_file("/tmp/a", "pam_sm_chauthtok") or { return 0 }
    return C.PAM_SUCCESS
}
