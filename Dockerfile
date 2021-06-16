    FROM debian
    RUN useradd -m a -s /bin/bash &&\
        useradd -m b -s /bin/bash &&\
        apt update &&\
        apt install -y gcc libpam0g-dev vim libssl-dev libcjson-dev
