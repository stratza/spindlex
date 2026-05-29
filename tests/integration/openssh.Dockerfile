FROM alpine:3.20

RUN apk add --no-cache busybox-extras openssh-server openssh-sftp-server \
    && adduser -D -s /bin/sh testuser \
    && echo "testuser:password123" | chpasswd \
    && ssh-keygen -A \
    && mkdir -p /run/sshd \
    && printf '%s\n' \
        "Port 22" \
        "ListenAddress 0.0.0.0" \
        "PasswordAuthentication yes" \
        "PermitEmptyPasswords no" \
        "KbdInteractiveAuthentication no" \
        "UsePAM no" \
        "AllowTcpForwarding yes" \
        "GatewayPorts no" \
        "X11Forwarding no" \
        "Subsystem sftp internal-sftp" \
        > /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
