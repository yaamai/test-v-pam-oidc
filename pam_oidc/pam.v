module main

#include <security/pam_ext.h>
#flag -I @VMODROOT
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
