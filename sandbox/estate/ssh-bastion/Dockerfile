# Legacy branch-office jump host for the sandbox estate.
#
# A REAL SSH daemon with a deliberately dated cryptographic posture (sha1
# key exchange, ssh-rsa host-key signature, CBC ciphers, sha1 MACs) so
# CryptoScan's /network/ssh-scan produces the same class of findings it
# would against a bank's unmaintained bastion. Throwaway — sandbox only.
FROM alpine:3.20

RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && mkdir -p /var/empty/sshd \
    && adduser -D -s /sbin/nologin teller \
    && adduser -D -s /sbin/nologin batchops

COPY sshd_config /etc/ssh/sshd_config
COPY banner.txt /etc/ssh/banner.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
