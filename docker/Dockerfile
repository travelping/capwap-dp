FROM ubuntu:16.04 

COPY . /

RUN apt-get -qq update; \
    apt-get install-y build-essential \
            automake \
            autoconf \
            libtool \
            pkg-config \
            shtool \
            libev-dev \
            libsystemd-dev \
            erlang-dev \
            liburcu-dev \
            libconfig-dev;\
    cd /build;\
    ./autogen.sh;\
    ./configure --sysconfdir=/etc;\
    make ;\
    make install

#COPY docker/docker-entrypoint.sh /
COPY src/ergw-dp.conf /etc/

#ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["usr/bin/capwap-dp", "foreground"]

