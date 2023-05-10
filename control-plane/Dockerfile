FROM amazonlinux:2023
RUN yum -y update
RUN yum install -y aws-nitro-enclaves-cli wget

COPY ./control-plane .
RUN chmod a+x ./control-plane

COPY ./scripts/health-check.sh .
COPY ./scripts/start-cage.sh .
RUN chmod a+x ./start-cage.sh

EXPOSE 443
ENTRYPOINT ["./start-cage.sh"]
