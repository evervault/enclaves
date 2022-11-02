FROM amazonlinux:2

#Patch vuln https://alas.aws.amazon.com/AL2/ALAS-2022-1776.html
yum update golang

RUN amazon-linux-extras install -y aws-nitro-enclaves-cli
RUN yum -y update ; yum install wget -y

COPY ./control-plane .
RUN chmod a+x ./control-plane

COPY ./scripts/health-check.sh .
COPY ./scripts/start-cage.sh .
RUN chmod a+x ./start-cage.sh

EXPOSE 443
ENTRYPOINT ["./start-cage.sh"]
