FROM amazonlinux:1
MAINTAINER Maskopy Contributors
USER root

ENV APP_USER=maskopy

RUN yum install openssl -y
RUN /usr/bin/openssl req -x509 -nodes -days 365 \
    -subj  "/CN=localhost" \
    -newkey rsa:2048 \
    -keyout "/etc/pki/tls/private/selfsigned.key" \
    -out "/etc/pki/tls/certs/selfsigned.crt"
RUN yum install aws-cli \
                gcc \
                glibc.i686 \
                glibc-devel.i686 \
                libaio.i686 \
                libstdc++44.i686 \
                mailx \
                perl.x86_64 \
                postgresql \
                shadow-utils \
                sudo \
                tar \
                unzip -y

COPY config-bootstrap.sh /tmp/
RUN useradd ${APP_USER} && \
    chmod 755 /tmp/*.sh && \
    cp /home/maskopy/.bash_profile /root/.bash_profile
