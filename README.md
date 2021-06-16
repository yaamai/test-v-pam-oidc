# test-v-pam-oidc

```
# docker run --rm -itd --network host -e HYDRA_ADMIN_URL=http://localhost:4445 oryd/hydra-login-consent-node:v1.3.2
# docker run --rm -itd --network host -e DSN=memory -e URLS_SELF_ISSUER=http://localhost:4444/ -e URLS_CONSENT=http://localhost:3000/consent -e URLS_LOGIN=http://localhost:3000/login  oryd/hydra:v1.10.2-sqlite serve --sqa-opt-out --dangerous-force-http all
# docker run --rm -it --network host -e HYDRA_URL=http://localhost:4445 oryd/hydra:v1.10.2-sqlite clients delete test
# docker run --rm -it --network host -e HYDRA_URL=http://localhost:4445 oryd/hydra:v1.10.2-sqlite clients create --id test --secret some-secret --grant-types authorization_code,refresh_token,client_credentials,implicit --response-types token,code,id_token --scope openid,offline --callbacks http://localhost:3000/ --token-endpoint-auth-method client_secret_post

# v -shared -prod -o out.c
# gcc -fPIC -o /lib/x86_64-linux-gnu/security/pam_oidc.so -shared -lpam -lssl out.c
```
