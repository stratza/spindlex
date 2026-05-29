FROM alpine:3.20

RUN apk add --no-cache busybox-extras dropbear openssh-sftp-server \
    && adduser -D -s /bin/sh testuser \
    && echo "testuser:password123" | chpasswd

EXPOSE 22

CMD ["/usr/sbin/dropbear", "-F", "-E", "-R", "-p", "0.0.0.0:22"]
