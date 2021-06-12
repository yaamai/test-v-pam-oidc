
import os




#include <security/pam_modules.h>
#include "types.h"

[export: 'pam_sm_authenticate']
fn pam_sm_authenticate(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    os.write_file("/tmp/a", "pam_sm_authenticate") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_setcred']
fn pam_sm_setcred(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    os.write_file("/tmp/a", "pam_sm_setcred") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_acct_mgmt']
fn pam_sm_acct_mgmt(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    os.write_file("/tmp/a", "pam_sm_acct_mgmt") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_open_session']
fn pam_sm_open_session(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    os.write_file("/tmp/a", "pam_sm_open_session") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_close_session']
fn pam_sm_close_session(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    os.write_file("/tmp/a", "pam_sm_close_session") or { return 0 }
    return C.PAM_SUCCESS
}

[export: 'pam_sm_chauthtok']
fn pam_sm_chauthtok(handle &C.pam_handle_t, flags int, argc int, args &&C.cchar) int {
    os.write_file("/tmp/a", "pam_sm_chauthtok") or { return 0 }
    return C.PAM_SUCCESS
}
