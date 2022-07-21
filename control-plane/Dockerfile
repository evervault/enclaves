FROM amazonlinux:2

RUN amazon-linux-extras install -y aws-nitro-enclaves-cli
RUN yum -y update

COPY ./control-plane .
RUN chmod a+x ./control-plane

COPY ./scripts/start-cage.sh .
RUN chmod a+x ./start-cage.sh

EXPOSE 443
ENTRYPOINT ["./start-cage.sh"]