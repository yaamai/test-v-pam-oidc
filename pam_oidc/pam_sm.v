module main

import os

#include <security/pam_modules.h>

[export: 'pam_sm_authenticate']
fn export_pam_sm_authenticate(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    // if define C.pam_handle_t in vlang, conflict occur with function definitions. (maybe vlang bug?)
    mut pam := unsafe { PAM{handle: handle} }
    return pam_sm_authenticate(mut pam, flags, parse_pam_args(argc, args)) or {
        C.pam_prompt(handle, C.PAM_ERROR_MSG, voidptr(0), "ERROR: ${err}".str)
        s := "ERROR: ${err}\n"
        os.write_file("/tmp/pam_oidc.log", os.read_file("/tmp/pam_oidc.log") or {""} + s) or {}
        return C.PAM_AUTH_ERR
    }
}

[export: 'pam_sm_setcred']
fn export_pam_sm_setcred(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    // if define C.pam_handle_t in vlang, conflict occur with function definitions. (maybe vlang bug?)
    mut pam := unsafe { PAM{handle: handle} }
    return pam_sm_setcred(mut pam, flags, parse_pam_args(argc, args)) or {
        C.pam_prompt(handle, C.PAM_ERROR_MSG, voidptr(0), "ERROR: ${err}".str)
        return C.PAM_CRED_ERR
    }
}

[export: 'pam_sm_acct_mgmt']
fn export_pam_sm_acct_mgmt(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    // if define C.pam_handle_t in vlang, conflict occur with function definitions. (maybe vlang bug?)
    mut pam := unsafe { PAM{handle: handle} }
    return pam_sm_acct_mgmt(mut pam, flags, parse_pam_args(argc, args)) or {
        C.pam_prompt(handle, C.PAM_ERROR_MSG, voidptr(0), "ERROR: ${err}".str)
        return C.PAM_AUTH_ERR
    }
}

[export: 'pam_sm_open_session']
fn export_pam_sm_open_session(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    // if define C.pam_handle_t in vlang, conflict occur with function definitions. (maybe vlang bug?)
    mut pam := unsafe { PAM{handle: handle} }
    return pam_sm_open_session(mut pam, flags, parse_pam_args(argc, args)) or {
        C.pam_prompt(handle, C.PAM_ERROR_MSG, voidptr(0), "ERROR: ${err}".str)
        return C.PAM_SESSION_ERR
    }
}

[export: 'pam_sm_close_session']
fn export_pam_sm_close_session(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    // if define C.pam_handle_t in vlang, conflict occur with function definitions. (maybe vlang bug?)
    mut pam := unsafe { PAM{handle: handle} }
    return pam_sm_close_session(mut pam, flags, parse_pam_args(argc, args)) or {
        C.pam_prompt(handle, C.PAM_ERROR_MSG, voidptr(0), "ERROR: ${err}".str)
        return C.PAM_SESSION_ERR
    }
}

[export: 'pam_sm_chauthtok']
fn export_pam_sm_chauthtok(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    // if define C.pam_handle_t in vlang, conflict occur with function definitions. (maybe vlang bug?)
    mut pam := unsafe { PAM{handle: handle} }
    return pam_sm_chauthtok(mut pam, flags, parse_pam_args(argc, args)) or {
        C.pam_prompt(handle, C.PAM_ERROR_MSG, voidptr(0), "ERROR: ${err}".str)
        return C.PAM_AUTHTOK_ERR
    }
}
