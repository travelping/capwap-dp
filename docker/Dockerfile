FROM bitwalker/alpine-erlang:20.1 AS build-env

RUN mkdir /src && \
    apk update && \
    apk upgrade --no-cache  && \
    apk add --no-cache gcc build-base automake autoconf libtool pkgconf make linux-headers \
		       libconfig-dev \
		       libev-dev \
		       userspace-rcu-dev
RUN cd /src && \
    wget -O - ftp://ftp.gnu.org/gnu/shtool/shtool-2.0.8.tar.gz | tar xzf - && \
    cd shtool-2.0.8 && \
    ./configure --prefix=/usr && \
    make && \
    make install
ADD . /src/capwap-dp
RUN cd /src/capwap-dp && \
    ./autogen.sh && \
    ./configure --prefix=/usr --sysconfdir=/etc/capwap-dp && \
    make && \
    make install DESTDIR=/src/capwap-dp/build && \
    ls -lR build && \
    ldd /src/capwap-dp/build/usr/bin/capwap-dp

FROM alpine:latest
WORKDIR /
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache libconfig libev userspace-rcu
COPY --from=build-env /src/capwap-dp/build /
ENTRYPOINT /usr/bin/capwap-dp