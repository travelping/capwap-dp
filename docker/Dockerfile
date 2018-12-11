FROM alpine:3.8 AS build-env

RUN mkdir /src && \
    apk update && \
    apk upgrade --no-cache  && \
    apk add --no-cache gcc build-base automake autoconf libtool pkgconf make linux-headers \
		       erlang-dev \
		       libconfig-dev \
		       libev-dev \
		       userspace-rcu-dev
RUN cd /src && \
    wget -O - http://ftp.gnu.org/gnu/shtool/shtool-2.0.8.tar.gz | tar xzf - && \
    cd shtool-2.0.8 && \
    ./configure --prefix=/usr && \
    make && \
    make install

# build capwap-dp
ADD . /src/capwap-dp
WORKDIR src/capwap-dp
RUN ./autogen.sh && \
    ./configure --prefix=/usr --sysconfdir=/etc/capwap-dp --enable-debug && \
    make && \
    make install DESTDIR=/src/capwap-dp/build
# split binary into <binary> and <binary.debug> (a file which contains the
# debug symbols)
WORKDIR /src/capwap-dp/build/usr/bin/
RUN objcopy --only-keep-debug capwap-dp capwap-dp.debug && \
    strip --strip-debug --strip-unneeded capwap-dp && \
    objcopy --add-gnu-debuglink=capwap-dp.debug capwap-dp

RUN find /src/capwap-dp/build

FROM alpine:3.8
WORKDIR /
ADD ./docker/entrypoint.sh /entrypoint.sh
RUN apk --update --no-cache add libconfig libev userspace-rcu iproute2 bridge-utils
COPY --from=build-env /src/capwap-dp/build /
ENTRYPOINT [ "/entrypoint.sh" ]
