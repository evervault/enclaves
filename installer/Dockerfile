FROM --platform=linux/amd64 alpine

RUN mkdir -p /packages
RUN apk update ; apk add xz make gcc build-base bash linux-headers curl pkgconfig

ADD http://smarden.org/runit/runit-2.1.2.tar.gz /packages/runit-2.1.2.tar.gz
ADD https://downloads.sourceforge.net/project/net-tools/net-tools-2.10.tar.xz /packages/net-tools-2.10.tar.xz

RUN curl -o /packages/libmnl-1.0.4.tar.bz2 https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.4.tar.bz2
RUN curl -o /packages/iptables-1.8.10.tar.xz https://www.netfilter.org/projects/iptables/files/iptables-1.8.10.tar.xz
RUN curl -o /packages/libnftnl-1.2.6.tar.xz https://www.netfilter.org/projects/libnftnl/files/libnftnl-1.2.6.tar.xz

# Copy in minimal preset header file to configure net-tools compilation
COPY config/net-tools.h /packages/

COPY scripts/installer.sh /packages
RUN chmod +x /packages/installer.sh

COPY scripts/compile-runtime-dependencies.sh /compile-runtime-dependencies.sh
RUN chmod +x /compile-runtime-dependencies.sh

ENTRYPOINT [ "/compile-runtime-dependencies.sh" ]