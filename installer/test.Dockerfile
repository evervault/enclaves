FROM ubuntu 

RUN mkdir -p /opt/evervault
COPY output/runtime-dependencies.tar.gz /opt/evervault
RUN cd /opt/evervault ; \
 gunzip runtime-dependencies.tar.gz ; \
 tar -xf runtime-dependencies.tar ; \
 sh installer.sh
