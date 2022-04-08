# test-v-pam-oidc
PoC OIDC(OpenID Connect) PAM authentication module written in vlang.

## testing
### build testbed image
```console
[host] # git clone https://github.com/yaamai/test-v-pam-oidc
[host] # docker build . -t localhost/test-v-pam-oidc:latest-testbed
```

### prepare OIDC server
```
[host] # docker run --rm -itd --network host -e HYDRA_ADMIN_URL=http://localhost:4445 oryd/hydra-login-consent-node:v1.3.2
[host] # docker run --rm -itd --network host -e DSN=memory -e URLS_SELF_ISSUER=http://localhost:4444/ -e URLS_CONSENT=http://localhost:3000/consent -e URLS_LOGIN=http://localhost:3000/login  oryd/hydra:v1.10.2-sqlite serve --sqa-opt-out --dangerous-force-http all
[host] # docker run --rm -it --network host -e HYDRA_URL=http://localhost:4445 oryd/hydra:v1.10.2-sqlite clients delete test
[host] # docker run --rm -it --network host -e HYDRA_URL=http://localhost:4445 oryd/hydra:v1.10.2-sqlite clients create --id test --secret some-secret --grant-types authorization_code,refresh_token,client_credentials,implicit --response-types token,code,id_token --scope openid,offline --callbacks http://localhost:3000/ --token-endpoint-auth-method client_secret_post
```

### test login (su)
```
[host]      # docker run --rm -it --net host -v $PWD:/work -w /work localhost/test-v-pam-oidc:latest-testbed
[container] # su - a
[container] $ su - b
Password: **(press Ctrl+d to skip normal password auth)**
please open and sign-in "http://localhost:4444/oauth2/auth?client_id=test&redirect_uri=http0X0.07FFFE46F904P-10220.0000000.000000localhost0X0.000010000000EP-102244440.000000callback&scope=openid+offline&response_type&state=556af8b571584a8f&nonce=28bb51d84a71b023".
Redirected URL:
ERROR: net.urllib.parse: failed parsing url
su: Authentication failure
```

### re-build or debugging
```console
[container] # v version
V 0.2.4 6425000
[container] # ls
Dockerfile  README.md  memo.txt  old  pam_oidc  pam_oidc.so
[container] # v -cg -prod -shared -o /lib/x86_64-linux-gnu/security/pam_oidc.so pam_oidc/
[container] # ls -al /lib/x86_64-linux-gnu/security/pam_oidc.so
-rwxr-xr-x 1 root root 2631976 Apr  8 07:23 /lib/x86_64-linux-gnu/security/pam_oidc.so
```

