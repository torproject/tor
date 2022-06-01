FROM alpine:edge as builder
COPY ./ /usr/src/tor
WORKDIR /usr/src/tor
RUN \
apk add --no-cache --virtual .torbuild build-base libcap-dev libseccomp-dev libevent-dev openssl1.1-compat-dev ca-certificates zlib-dev xz-dev zstd-dev git automake autoconf asciidoc nss-dev libevent-static zlib-static openssl-libs-static zstd-static nss-static nss-tools libseccomp-dev libseccomp-static libcap-ng-dev libcap-ng-static libcap-dev libcap-static && \
#mkdir -p /usr/src && \
#cd /usr/src && \
#git clone --branch automerge https://github.com/maxisoft/tor.git && \
#cd tor && \
./autogen.sh && \
./configure  --disable-asciidoc --enable-static-tor --enable-static-libevent --enable-static-openssl --enable-static-zlib --disable-module-relay --disable-module-dirauth --disable-html-manual --disable-unittests --with-libevent-dir=/usr/lib --with-zlib-dir=/lib --with-openssl-dir=/usr/lib && \
make && \
make install && \
apk del .torbuild && \
cd .. && \
rm -rf /usr/src/tor
COPY ./ /usr/src/tor

FROM alpine:edge
LABEL maintainer="github.com/maxisoft" name="tor custom build" url="https://github.com/maxisoft/tor" vcs-url="https://github.com/maxisoft/tor" org.opencontainers.image.source="https://github.com/maxisoft/tor"
RUN apk add --no-cache tor
COPY --from=builder /usr/local/bin/tor /usr/bin/tor
ENTRYPOINT [ "/usr/bin/tor" ]