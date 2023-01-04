FROM alpine

RUN mkdir -p /packages
RUN apk update ; apk add xz make gcc build-base bash linux-headers

ADD http://smarden.org/runit/runit-2.1.2.tar.gz /packages/runit-2.1.2.tar.gz
ADD https://downloads.sourceforge.net/project/net-tools/net-tools-2.10.tar.xz /packages/net-tools-2.10.tar.xz

# Copy in minimal preset header file to configure net-tools compilation
COPY config/net-tools.h /packages/

RUN mkdir -p /output
COPY scripts/installer.sh /packages
RUN chmod +x /packages/installer.sh

COPY scripts/compile-runtime-dependencies.sh /compile-runtime-dependencies.sh
RUN chmod +x /compile-runtime-dependencies.sh

ENTRYPOINT [ "/compile-runtime-dependencies.sh" ]