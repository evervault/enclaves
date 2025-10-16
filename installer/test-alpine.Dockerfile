FROM --platform=amd64 alpine:3.22.1 

RUN mkdir -p /opt/evervault
COPY output/runtime-dependencies.tar.gz /opt/evervault
RUN cd /opt/evervault ; \
 gunzip runtime-dependencies.tar.gz ; \
 tar -xf runtime-dependencies.tar ; \
 sh installer.sh

COPY scripts/test-installer.sh /test-installer.sh

ENTRYPOINT [ "sh", "/test-installer.sh" ]