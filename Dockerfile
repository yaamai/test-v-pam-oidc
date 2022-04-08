FROM thevlang/vlang:buster-dev
RUN apt-get update &&\
    apt-get install -y libpam0g-dev &&\
    mkdir -p /app &&\
    useradd -m a -s /bin/bash &&\
    useradd -m b -s /bin/bash
RUN sed -i /etc/pam.d/common-password -e '/pam_unix.so/a password        sufficient                       pam_oidc.so' &&\
    sed -i /etc/pam.d/common-auth -e '/pam_unix.so/a auth    sufficient                       pam_oidc.so oidc_config_url=http://localhost:4444/.well-known/openid-configuration client_id=test client_secret=some-secret redirect_uri=http://localhost:3000/ scope=openid,offline response_type=code mapping=/etc/mapping' &&\
    echo '{"foo@bar.com": "b"}' > /etc/mapping

WORKDIR /app
COPY pam_oidc /app/pam_oidc
RUN v -cg -prod -shared -o /lib/x86_64-linux-gnu/security/pam_oidc.so pam_oidc/
