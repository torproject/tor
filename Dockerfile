FROM alpine:edge as builder
ARG DEFAULT_ROUTE_LEN=2
ARG CFLAGS="-Ofast -finline-functions -funroll-loops"
ENV DEFAULT_ROUTE_LEN=${DEFAULT_ROUTE_LEN} CFLAGS="${CFLAGS}"
COPY ./ /usr/src/tor
WORKDIR /usr/src/tor
RUN \
export CXXFLAGS="${CFLAGS}" && \
apk add --no-cache --virtual .torbuild build-base libcap-dev libseccomp-dev libevent-dev openssl1.1-compat-dev ca-certificates zlib-dev xz-dev zstd-dev git automake autoconf asciidoc nss-dev libevent-static zlib-static openssl-libs-static zstd-static nss-static nss-tools libseccomp-dev libseccomp-static libcap-ng-dev libcap-ng-static libcap-dev libcap-static && \
#mkdir -p /usr/src && \
#cd /usr/src && \
#git clone --branch automerge https://github.com/maxisoft/tor.git && \
#cd tor && \
sed -i "s/#define[[:space:]]\+DEFAULT_ROUTE_LEN[[:space:]]\+[[:digit:]]\+/#define DEFAULT_ROUTE_LEN $DEFAULT_ROUTE_LEN/gw orhchanges.txt" "src/core/or/or.h" && \
cat orhchanges.txt && \
./autogen.sh && \
./configure --disable-asciidoc --enable-static-tor --enable-static-libevent --enable-static-openssl --enable-static-zlib --disable-module-relay --disable-module-dirauth --disable-html-manual --disable-unittests --with-libevent-dir=/usr/lib --with-zlib-dir=/lib --with-openssl-dir=/usr/lib && \
make && \
make install && \
apk del .torbuild && \
cd .. && \
rm -rf /usr/src/tor
#COPY ./ /usr/src/tor

FROM alpine:edge
ARG DEFAULT_ROUTE_LEN=2
LABEL maintainer="github.com/maxisoft" tor_route_len=${DEFAULT_ROUTE_LEN} name="tor custom build" url="https://github.com/maxisoft/tor" vcs-url="https://github.com/maxisoft/tor" org.opencontainers.image.source="https://github.com/maxisoft/tor"
RUN apk add --no-cache tor
COPY --from=builder /usr/local/bin/tor /usr/bin/tor
ENTRYPOINT [ "/usr/bin/tor" ]