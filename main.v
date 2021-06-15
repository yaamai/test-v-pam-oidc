import os


#include <security/pam_modules.h>
#include "types.h"
fn C.pam_get_user(handle &C.pam_handle_t, user &&C.cchar, prompt &C.cchar) int
fn C.pam_get_authtok(handle &C.pam_handle_t, item int, token &&C.cchar, prompt &C.cchar) int
fn C.pam_get_item(handle &C.pam_handle_t, item_type int, item &voidptr) int
fn C.pam_prompt(handle &C.pam_handle_t, style int, resp &&char, fmt &C.cchar) int

struct PAM {
handle &C.pam_handle_t
}

fn (mut p PAM) get_user(prompt string) ?string {
    user_ptr := &C.cchar(0)
    rc := C.pam_get_user(p.handle, &user_ptr, prompt.str)
    if rc != 0 {
        return error('')
    }
    return unsafe { cstring_to_vstring(&char(user_ptr)) }
}

fn (mut p PAM) get_authtok(prompt string) ?string {
    out := &C.cchar(0)
    rc := C.pam_get_authtok(p.handle, C.PAM_AUTHTOK, &out, prompt.str)
    if rc != 0 {
        return error('')
    }
    return unsafe { cstring_to_vstring(&char(out)) }
}

fn (mut p PAM) prompt(style int, fmt string) ?string {
    out := &char(0)
    rc := C.pam_prompt(p.handle, style, &out, fmt.str)
    if rc != 0 {
        return error('')
    }
    if out != 0 {
        return unsafe { cstring_to_vstring(&char(out)) }
    }
    return ""
}


[export: 'pam_sm_authenticate']
fn pam_sm_authenticate(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    mut pam := unsafe { PAM{handle: handle} }
    pam.prompt(C.PAM_TEXT_INFO, "hogehoe: ") or { return 0 }
    user := pam.get_user("") or { return 0 }
    token := pam.get_authtok("Password: ") or { return 0 }
    println("${user}, ${token}")

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
