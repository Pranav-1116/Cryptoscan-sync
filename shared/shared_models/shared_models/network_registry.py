"""Network protocol / service registry — every network service the scanner
can identify, with its IANA port(s), transport, category, encryption and a
deterministic risk verdict.

Single source of truth for naming and classifying a listening service from
any evidence the scanner already collects passively (port number, service
name, banner). It mirrors :mod:`algorithm_registry` for crypto primitives:

    ("http",  80)  -> HTTP,  cleartext web, DISALLOWED (use HTTPS)
    ("https",443)  -> HTTPS, TLS web,      ALLOWED
    ("rdp",  3389) -> RDP,   remote admin, RESTRICTED (NLA + gateway)
    ("modbus",502) -> Modbus, OT/ICS,      RESTRICTED (passive; never probe
                                                     safety systems)

Every lookup returns :class:`ProtocolInfo`. Unknown port/service degrades
gracefully to ``status="UNKNOWN"`` with ``exposure="unknown"`` — never
silently treated as safe. Classification is *passive*: it only interprets
the port/name/banner the discovery sweep already observed; it never causes a
new active probe (OT/SIS/ESD stay untouched).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# verdicts (aligned with the algorithm-registry / finding penalties)
# --------------------------------------------------------------------------- #
DISALLOWED = "DISALLOWED"   # cleartext or broken — must not be exposed
DEPRECATED = "DEPRECATED"   # obsolete / known-weak — migrate
RESTRICTED = "RESTRICTED"   # acceptable only with controls (segmentation, VPN, auth)
ALLOWED = "ALLOWED"         # secure-by-default service
UNKNOWN = "UNKNOWN"         # unrecognized — human review

TCP = "tcp"
UDP = "udp"
SCTP = "sctp"

#: how reachable the service is
INTERNET = "internet"        # designed for / commonly exposed to the internet
INTERNAL = "internal"        # internal-only; internet exposure is a finding
OT_SAFETY = "ot-safety"      # industrial control; passive-only, never probe


@dataclass(frozen=True)
class _Proto:
    canonical: str
    port: int
    transport: str
    category: str
    status: str
    encrypted: bool
    exposure: str
    alt_ports: tuple[int, ...] = ()
    aliases: tuple[str, ...] = ()
    notes: str = ""


# canonical catalog. Port is the IANA-assigned default; alt_ports hold the
# other ports the same service routinely appears on.
_PROTOCOLS: dict[tuple[int, str], _Proto] = {}
_BY_ALIAS: dict[str, "_Proto"] = {}


def _add(
    canonical: str,
    port: int,
    transport: str,
    category: str,
    status: str,
    encrypted: bool,
    exposure: str,
    alt_ports: tuple[int, ...] = (),
    aliases: tuple[str, ...] = (),
    notes: str = "",
) -> _Proto:
    p = _Proto(canonical, port, transport, category, status, encrypted, exposure,
               alt_ports=alt_ports, aliases=aliases, notes=notes)
    # First-registered wins on a shared port (e.g. HTTPS owns 443 over SSTP/DoH).
    _PROTOCOLS.setdefault((port, transport), p)
    for ap in alt_ports:
        _PROTOCOLS.setdefault((ap, transport), p)
    for alias in aliases:
        _BY_ALIAS.setdefault(_nk(alias), p)
    _BY_ALIAS.setdefault(_nk(canonical), p)
    return p


def _nk(name: str) -> str:
    return "".join(ch for ch in str(name).upper() if ch.isalnum())


# -- web -------------------------------------------------------------------- #
_add("HTTP", 80, TCP, "web", DISALLOWED, False, INTERNET,
     alt_ports=(8008, 8080), aliases=("www", "www-http", "http-proxy"),
     notes="cleartext HTTP — redirect to HTTPS (HSTS)"),
_add("HTTPS", 443, TCP, "web", ALLOWED, True, INTERNET,
     alt_ports=(8443,), aliases=("tls", "ssl", "https-tls"),
     notes="HTTP over TLS"),
_add("HTTP-Alt (cleartext)", 8080, TCP, "web", DISALLOWED, False, INTERNAL,
     aliases=("http-alt", "http-proxy-alt"), notes="common cleartext admin/web port"),
_add("HTTPS-Alt", 8443, TCP, "web", ALLOWED, True, INTERNAL,
     aliases=("https-alt",), notes="alt HTTPS (appliances, admin UIs)"),

# -- mail ------------------------------------------------------------------- #
_add("SMTP", 25, TCP, "mail", DISALLOWED, False, INTERNET,
     aliases=("mail", "smtp-mta"), notes="cleartext MTA; require STARTTLS"),
_add("SMTPS", 465, TCP, "mail", ALLOWED, True, INTERNET,
     aliases=("smtps", "smtp-ssl"), notes="SMTP implicit TLS"),
_add("SMTP Submission", 587, TCP, "mail", ALLOWED, True, INTERNET,
     aliases=("submission", "smtp-submission"), notes="STARTTLS required"),
_add("POP3", 110, TCP, "mail", DISALLOWED, False, INTERNAL,
     aliases=("pop3",), notes="cleartext POP3; use POP3S/STARTTLS"),
_add("POP3S", 995, TCP, "mail", ALLOWED, True, INTERNAL,
     aliases=("pop3s",), notes="POP3 over TLS"),
_add("IMAP", 143, TCP, "mail", DISALLOWED, False, INTERNAL,
     aliases=("imap", "imap2"), notes="cleartext IMAP; use IMAPS/STARTTLS"),
_add("IMAPS", 993, TCP, "mail", ALLOWED, True, INTERNAL,
     aliases=("imaps",), notes="IMAP over TLS"),

# -- file transfer / sharing ------------------------------------------------ #
_add("FTP", 21, TCP, "file-transfer", DISALLOWED, False, INTERNAL,
     aliases=("ftp", "fsp"), notes="cleartext credentials/data; use SFTP/FTPS"),
_add("FTPS", 990, TCP, "file-transfer", RESTRICTED, True, INTERNAL,
     aliases=("ftps", "ftp-ssl"), notes="FTP over TLS; prefer SFTP"),
_add("FTP data", 20, TCP, "file-transfer", DISALLOWED, False, INTERNAL, notes="FTP active data channel"),
# SFTP is a subsystem of SSH (port 22, owned by the SSH record below); the
# "sftp" name is registered as an SSH alias rather than a separate listener.
_add("SMB", 445, TCP, "file-sharing", DISALLOWED, False, INTERNAL,
     aliases=("microsoft-ds", "smb", "cifs"), notes="SMB must not face the internet (eternal-class risk); use SMB3 + VPN"),
_add("NetBIOS Session", 139, TCP, "file-sharing", DISALLOWED, False, INTERNAL,
     aliases=("netbios-ssn", "netbios"), notes="legacy NetBIOS; disable externally"),
_add("NetBIOS Name", 137, UDP, "name-service", DISALLOWED, False, INTERNAL,
     aliases=("netbios-ns",), notes="legacy NetBIOS naming"),
_add("NFS", 2049, TCP, "file-sharing", RESTRICTED, False, INTERNAL,
     aliases=("nfs", "nfsd", "nfs-tcp"), notes="network file system; restrict exports, never internet"),
_add("NFS (UDP)", 2049, UDP, "file-sharing", RESTRICTED, False, INTERNAL,
     aliases=("nfs-udp",), notes="NFS over UDP; restrict exports"),
_add("AFP", 548, TCP, "file-sharing", DEPRECATED, False, INTERNAL,
     aliases=("afp", "afpovertcp"), notes="Apple Filing Protocol; deprecated (use SMB)"),
_add("TFTP", 69, UDP, "file-transfer", DISALLOWED, False, INTERNAL,
     aliases=("tftp",), notes="unauthenticated UDP file transfer; provisioning only"),

# -- remote access / shells ------------------------------------------------- #
_add("SSH", 22, TCP, "remote-access", ALLOWED, True, INTERNET,
     alt_ports=(2222,), aliases=("ssh", "sshd", "ssh-remote", "sftp", "ssh-file-transfer"),
     notes="secure shell (carries SFTP/SCP); enforce key auth + modern KEX"),
_add("Telnet", 23, TCP, "remote-access", DISALLOWED, False, INTERNAL,
     aliases=("telnet",), notes="cleartext terminal; never use (use SSH)"),
_add("Rlogin", 513, TCP, "remote-access", DISALLOWED, False, INTERNAL,
     aliases=("rlogin", "login"), notes="cleartext r-services; disable"),
_add("Rsh/Rexec", 514, TCP, "remote-access", DISALLOWED, False, INTERNAL,
     aliases=("rsh", "shell", "rexec"), notes="cleartext remote shell; disable"),
_add("RDP", 3389, TCP, "remote-access", RESTRICTED, True, INTERNAL,
     aliases=("rdp", "ms-wbt-server", "ms-term-serv"), notes="require NLA + gateway; never raw to internet"),
_add("VNC", 5900, TCP, "remote-access", DISALLOWED, False, INTERNAL,
     alt_ports=tuple(range(5901, 5910)), aliases=("vnc", "vnc-server", "rfb"),
     notes="VNC is often cleartext; tunnel over SSH/VPN"),
_add("X11", 6000, TCP, "remote-access", DISALLOWED, False, INTERNAL,
     alt_ports=tuple(range(6001, 6010)), aliases=("x11", "x-window", "x-windows"),
     notes="X display; use SSH X-forwarding"),
_add("WinRM", 5985, TCP, "remote-access", DISALLOWED, False, INTERNAL,
     aliases=("wsman", "winrm-http"), notes="WinRM cleartext; use 5986 (HTTPS)"),
_add("WinRM HTTPS", 5986, TCP, "remote-access", RESTRICTED, True, INTERNAL,
     aliases=("winrm-https", "wsmans"), notes="WinRM over TLS"),

# -- naming / directory ----------------------------------------------------- #
_add("DNS", 53, UDP, "name-service", RESTRICTED, False, INTERNET,
     aliases=("domain", "dns"), notes="queries cleartext (DoT/DoH preferred); zone transfers restricted"),
_add("DNS-TCP", 53, TCP, "name-service", RESTRICTED, False, INTERNET,
     aliases=("domain-tcp",), notes="DNS over TCP (large responses/AXFR)"),
_add("DoT", 853, TCP, "name-service", ALLOWED, True, INTERNET,
     aliases=("dns-over-tls", "dot"), notes="DNS over TLS"),
_add("DoH", 443, TCP, "name-service", ALLOWED, True, INTERNET,
     aliases=("dns-over-https", "doh"), notes="DNS over HTTPS (rides HTTPS/443)"),
_add("mDNS", 5353, UDP, "name-service", RESTRICTED, False, INTERNAL,
     aliases=("mdns", "p2p"), notes="multicast DNS; local segment only"),
_add("LLMNR", 5355, UDP, "name-service", DISALLOWED, False, INTERNAL,
     aliases=("llmnr",), notes="poisoning-prone; disable"),
_add("LDAP", 389, TCP, "directory", DISALLOWED, False, INTERNAL,
     aliases=("ldap",), notes="cleartext directory; use LDAPS/StartTLS"),
_add("LDAPS", 636, TCP, "directory", RESTRICTED, True, INTERNAL,
     aliases=("ldaps", "ldap-ssl"), notes="LDAP over TLS"),
_add("LDAP GC", 3268, TCP, "directory", DISALLOWED, False, INTERNAL,
     aliases=("gc", "global-catalog"), notes="AD global catalog; use 3269"),
_add("LDAPS GC", 3269, TCP, "directory", RESTRICTED, True, INTERNAL,
     aliases=("gc-ssl", "global-catalog-ssl"), notes="AD global catalog over TLS"),
_add("Kerberos", 88, UDP, "authentication", ALLOWED, True, INTERNAL,
     alt_ports=(88,), aliases=("kerberos", "kerberos-sec", "krb5"), notes="Kerberos auth (UDP+TCP)"),
_add("NTP", 123, UDP, "time", RESTRICTED, False, INTERNET,
     aliases=("ntp",), notes="unauthenticated; use NTS / authenticated NTP"),

# -- databases / caches / messaging ----------------------------------------- #
_add("MySQL", 3306, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("mysql",), notes="require TLS; never internet-exposed"),
_add("PostgreSQL", 5432, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("postgres", "postgresql"), notes="require SSL (sslmode=verify-full)"),
_add("MSSQL", 1433, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("ms-sql-s", "sqlserver", "mssql"), notes="require encrypted connections"),
_add("Oracle DB", 1521, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("oracle", "oracle-tns", "tns"), notes="Oracle TNS listener; use TCPS/network encryption"),
_add("MongoDB", 27017, TCP, "database", DISALLOWED, False, INTERNAL,
     aliases=("mongodb", "mongo"), notes="historically no-auth by default; enforce auth+TLS"),
_add("Redis", 6379, TCP, "cache", DISALLOWED, False, INTERNAL,
     aliases=("redis",), notes="no auth by default; never expose; use TLS+ACL"),
_add("Memcached", 11211, TCP, "cache", DISALLOWED, False, INTERNAL,
     alt_ports=(11211,), aliases=("memcache", "memcached"), notes="UDP amplification risk; internal only"),
_add("Cassandra", 9042, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("cassandra", "cql"), notes="enable client-to-node TLS"),
_add("Elasticsearch", 9200, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("elasticsearch", "es-http"), notes="enable security/TLS + auth"),
_add("CouchDB", 5984, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("couchdb", "couch"), notes="require HTTPS + auth"),
_add("InfluxDB", 8086, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("influxdb", "influx"), notes="enable auth/TLS"),
_add("RabbitMQ AMQP", 5672, TCP, "messaging", DISALLOWED, False, INTERNAL,
     aliases=("amqp", "rabbitmq"), notes="cleartext AMQP; use AMQPS/5671"),
_add("AMQPS", 5671, TCP, "messaging", RESTRICTED, True, INTERNAL,
     aliases=("amqps", "amqp-ssl"), notes="AMQP over TLS"),
_add("MQTT", 1883, TCP, "messaging", DISALLOWED, False, INTERNET,
     aliases=("mqtt",), notes="cleartext IoT messaging; use MQTT-TLS/8883"),
_add("MQTT-TLS", 8883, TCP, "messaging", RESTRICTED, True, INTERNET,
     aliases=("mqtts", "secure-mqtt"), notes="MQTT over TLS"),
_add("Kafka", 9092, TCP, "messaging", RESTRICTED, False, INTERNAL,
     alt_ports=(9093,), aliases=("kafka", "kafka-plain"), notes="enable SASL_SSL"),

# -- network / infrastructure management ------------------------------------ #
_add("SNMP", 161, UDP, "monitoring", DISALLOWED, False, INTERNAL,
     aliases=("snmp", "snmp-agent"), notes="SNMP v1/v2c cleartext community strings; use SNMPv3"),
_add("SNMP Trap", 162, UDP, "monitoring", DISALLOWED, False, INTERNAL,
     aliases=("snmptrap", "snmp-trap"), notes="use SNMPv3 traps"),
_add("Syslog", 514, UDP, "logging", RESTRICTED, False, INTERNAL,
     aliases=("syslog",), notes="cleartext; use RFC5425 syslog-over-TLS/6514"),
_add("Syslog-TLS", 6514, TCP, "logging", ALLOWED, True, INTERNAL,
     aliases=("syslog-tls", "syslog-over-tls"), notes="RFC 5425"),
_add("NetFlow", 2055, UDP, "monitoring", RESTRICTED, False, INTERNAL,
     aliases=("netflow",), notes="telemetry export; collector segment"),
_add("sFlow", 6343, UDP, "monitoring", RESTRICTED, False, INTERNAL,
     aliases=("sflow",), notes="sampled flow telemetry"),
_add("ICAP", 1344, TCP, "proxy", RESTRICTED, False, INTERNAL,
     aliases=("icap",), notes="content adaptation; internal"),
_add("SOCKS", 1080, TCP, "proxy", RESTRICTED, False, INTERNAL,
     aliases=("socks", "socks5"), notes="proxy; authenticate + restrict"),
_add("IRC", 6667, TCP, "chat", DISALLOWED, False, INTERNET,
     alt_ports=(6668, 6669), aliases=("irc", "ircd"), notes="cleartext chat; use IRC-over-TLS/6697"),
_add("IRCS", 6697, TCP, "chat", RESTRICTED, True, INTERNET,
     aliases=("ircs", "irc-tls"), notes="IRC over TLS"),

# -- VPN / tunneling -------------------------------------------------------- #
_add("IPsec IKE", 500, UDP, "vpn", ALLOWED, True, INTERNET,
     aliases=("isakmp", "ike", "ipsec"), notes="IKE/ISAKMP key exchange"),
_add("IPsec NAT-T", 4500, UDP, "vpn", ALLOWED, True, INTERNET,
     aliases=("ipsec-nat-t", "non500-isakmp"), notes="IPsec NAT traversal"),
_add("WireGuard", 51820, UDP, "vpn", ALLOWED, True, INTERNET,
     aliases=("wireguard", "wg"), notes="modern VPN (modern crypto)"),
_add("OpenVPN", 1194, UDP, "vpn", ALLOWED, True, INTERNET,
     alt_ports=(1194,), aliases=("openvpn", "ovpn"), notes="OpenVPN (UDP/TCP)"),
_add("PPTP", 1723, TCP, "vpn", DISALLOWED, False, INTERNET,
     aliases=("pptp", "point-to-point-tunneling"), notes="broken (MS-CHAPv2/MPPE); disallow"),
_add("L2TP", 1701, UDP, "vpn", DISALLOWED, False, INTERNET,
     aliases=("l2tp", "l2f"), notes="no encryption alone; with IPsec only"),
_add("SSTP", 443, TCP, "vpn", RESTRICTED, True, INTERNET,
     aliases=("sstp",), notes="MS VPN over TLS (rides 443)"),

# -- remote procedure / API ------------------------------------------------- #
_add("gRPC", 50051, TCP, "rpc", RESTRICTED, False, INTERNAL,
     alt_ports=(50051,), aliases=("grpc",), notes="enable mTLS"),
_add("gRPC-TLS", 50052, TCP, "rpc", ALLOWED, True, INTERNAL,
     aliases=("grpcs", "grpc-tls"), notes="gRPC over TLS"),
_add("Thrift", 9090, TCP, "rpc", RESTRICTED, False, INTERNAL,
     aliases=("thrift",), notes="enable TLS"),
_add("etcd", 2379, TCP, "coordination", RESTRICTED, False, INTERNAL,
     aliases=("etcd", "etcd-client"), notes="cluster control plane; mTLS, never internet"),
_add("etcd peer", 2380, TCP, "coordination", RESTRICTED, False, INTERNAL,
     aliases=("etcd-peer",), notes="etcd peer replication"),
_add("Docker API", 2375, TCP, "container", DISALLOWED, False, INTERNAL,
     aliases=("docker", "docker-api"), notes="unauthenticated Docker daemon; use 2376/TLS or socket"),
_add("Docker API TLS", 2376, TCP, "container", RESTRICTED, True, INTERNAL,
     aliases=("docker-tls", "docker-api-tls"), notes="Docker over TLS w/ client certs"),
_add("Kubernetes API", 6443, TCP, "container", RESTRICTED, True, INTERNAL,
     aliases=("kubernetes", "k8s-api", "kube-apiserver"), notes="API server; RBAC + network policy"),
_add("Kubelet", 10250, TCP, "container", DISALLOWED, True, INTERNAL,
     aliases=("kubelet",), notes="node agent; restrict + auth"),

# -- OT / ICS / SCADA (passive-first; SIS/ESD never probed) ----------------- #
_add("Modbus TCP", 502, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("modbus", "modbus-tcp"), notes="OT control; passive observation only; segment"),
_add("S7 (Siemens)", 102, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("s7", "iso-on-tcp", "siemens-s7"), notes="Siemens S7 PLC; passive only"),
_add("DNP3", 20000, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("dnp3", "dnp"), notes="electric SCADA; secure-auth version; passive"),
_add("EtherNet/IP", 44818, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("ethernet-ip", "enip", "ab-etn-ip"), notes="Allen-Bradley / CIP; passive"),
_add("OPC UA", 4840, TCP, "ot-ics", RESTRICTED, True, OT_SAFETY,
     alt_ports=(4840, 4843), aliases=("opcua", "opc-ua", "opcua-tcp"), notes="encrypted OT channel; passive"),
_add("OPC Classic (DCOM)", 135, TCP, "ot-ics", DISALLOWED, False, OT_SAFETY,
     aliases=("msrpc", "dcom", "epmap", "opc-classic"), notes="DCE/RPC endpoint mapper (OPC Classic); avoid"),
_add("BACnet", 47808, UDP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("bacnet",), notes="building automation; BACnet Secure Connect preferred"),
_add("Foxboro/Trident", 20547, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("foxboro", "trident"), notes="safety system; NEVER actively probe"),
_add("IEC 60870-5-104", 2404, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("iec104", "iec-60870", "104"), notes="power-grid telecontrol; passive"),
_add("IEC 61850 MMS", 102, TCP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("mms", "iec61850"), notes="substation automation (shares 102); passive"),
_add("Profinet", 34962, UDP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     alt_ports=(34963, 34964), aliases=("profinet", "pn-rt"), notes="industrial Ethernet; passive"),
_add("EtherCAT", 34980, UDP, "ot-ics", RESTRICTED, False, OT_SAFETY,
     aliases=("ethercat",), notes="real-time fieldbus; passive"),

# -- legacy / high-risk cleartext ------------------------------------------ #
_add("Finger", 79, TCP, "information", DISALLOWED, False, INTERNET,
     aliases=("finger",), notes="user enumeration; disable"),
_add("Ident", 113, TCP, "authentication", DISALLOWED, False, INTERNET,
     aliases=("ident", "auth"), notes="legacy identd; rarely needed"),
_add("Chargen", 19, TCP, "information", DISALLOWED, False, INTERNET,
     aliases=("chargen", "ttytst"), notes="amplification abuse; disable"),
_add("Daytime", 13, TCP, "time", DEPRECATED, False, INTERNET,
     aliases=("daytime",), notes="legacy; use NTP/NTS"),
_add("Discard", 9, TCP, "information", DEPRECATED, False, INTERNAL,
     aliases=("discard", "sink"), notes="legacy test service"),
_add("BootP/DHCP server", 67, UDP, "network-config", RESTRICTED, False, INTERNAL,
     aliases=("bootps", "dhcp"), notes="DHCP server; secure/relay"),
_add("BootP/DHCP client", 68, UDP, "network-config", RESTRICTED, False, INTERNAL,
     aliases=("bootpc", "dhcp-client"), notes="DHCP client"),
_add("MSSQL Browser", 1434, UDP, "database", DISALLOWED, False, INTERNAL,
     aliases=("ms-sql-m", "sql-browser"), notes="info disclosure; disable if unused"),
_add("PostgreSQL stats", 5433, TCP, "database", RESTRICTED, False, INTERNAL,
     aliases=("postgres-alt",), notes="alt postgres"),


@dataclass(frozen=True)
class ProtocolInfo:
    """A classified network service."""

    raw: str
    canonical: str
    port: int | None
    transport: str
    category: str
    status: str = UNKNOWN
    encrypted: bool = False
    exposure: str = "unknown"
    recognized: bool = True
    notes: str = ""
    risk_reason: str = ""

    @property
    def cleartext(self) -> bool:
        return not self.encrypted

    @property
    def internet_exposure_risk(self) -> bool:
        """True when an internal/OT service is facing the internet."""
        return self.exposure in (INTERNAL, OT_SAFETY)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "protocol": self.canonical,
            "port": self.port,
            "transport": self.transport,
            "category": self.category,
            "status": self.status,
            "encrypted": self.encrypted,
            "cleartext": self.cleartext,
            "exposure": self.exposure,
            "recognized": self.recognized,
            "notes": self.notes,
            "risk_reason": self.risk_reason,
        }


def _unknown(raw: str, port: int | None, transport: str, reason: str = "") -> ProtocolInfo:
    return ProtocolInfo(
        raw=raw, canonical=raw or (f"port-{port}" if port else "unknown"),
        port=port, transport=transport, category="unknown", status=UNKNOWN,
        encrypted=False, exposure="unknown", recognized=False,
        risk_reason=reason or "unrecognized service — human review",
    )


def classify_port(port: int | str, transport: str = TCP) -> ProtocolInfo:
    """Classify a listening port (and optional transport) to a service."""
    try:
        p = int(str(port).split("/")[0].split()[0])
    except (ValueError, AttributeError):
        return _unknown(str(port), None, transport)
    t = str(transport).lower()
    rec = _PROTOCOLS.get((p, t)) or _PROTOCOLS.get((p, TCP)) or _PROTOCOLS.get((p, UDP))
    if rec is None:
        return _unknown(str(port), p, t)
    return ProtocolInfo(
        raw=f"{rec.canonical}/{p}", canonical=rec.canonical, port=p, transport=t,
        category=rec.category, status=rec.status, encrypted=rec.encrypted,
        exposure=rec.exposure, recognized=True, notes=rec.notes,
        risk_reason=_risk_reason(rec),
    )


# Banner/product tokens -> service record. Filled after all _add calls below
# by _build_banner_tokens(); covers versioned daemons (OpenSSH_9.0, nginx/1.24).
_BANNER_TOKEN: dict[str, "_Proto"] = {}

# Generic web-server product names. HTTP vs HTTPS is decided by the port
# (cleartext on 80/8080 vs TLS on 443/8443) when a port is known.
_WEB_SERVER_TOKENS = {
    "NGINX", "APACHE", "HTTPD", "IIS", "MICROSOFTIIS", "LIGHTTPD", "CADDY",
    "TOMCAT", "JETTY", "WEBSERVER", "TRAFFICSERVER", "VARNISH",
}


def _build_banner_tokens() -> None:
    if _BANNER_TOKEN:
        return
    tokens = {
        # SSH / remote
        "OPENSSH": _BY_ALIAS.get(_nk("ssh")), "SSHD": _BY_ALIAS.get(_nk("ssh")),
        "DROPBEAR": _BY_ALIAS.get(_nk("ssh")),
        # FTP daemons (cleartext)
        "PROFTPD": _BY_ALIAS.get(_nk("ftp")), "VSFTPD": _BY_ALIAS.get(_nk("ftp")),
        "WU-FTPD": _BY_ALIAS.get(_nk("ftp")), "FILEZILLA": _BY_ALIAS.get(_nk("ftp")),
        "PURE-FTPD": _BY_ALIAS.get(_nk("ftp")),
        # mail
        "POSTFIX": _BY_ALIAS.get(_nk("smtp")), "SENDMAIL": _BY_ALIAS.get(_nk("smtp")),
        "EXIM": _BY_ALIAS.get(_nk("smtp")), "DOVECOT": _BY_ALIAS.get(_nk("imaps")),
        # databases / caches
        "MYSQLD": _BY_ALIAS.get(_nk("mysql")), "MARIADB": _BY_ALIAS.get(_nk("mysql")),
        "POSTGRES": _BY_ALIAS.get(_nk("postgres")),
        "MSSQL": _BY_ALIAS.get(_nk("mssql")), "ORACLE": _BY_ALIAS.get(_nk("oracle")),
        "MONGOD": _BY_ALIAS.get(_nk("mongodb")),
        # remote desktop / sharing
        "RFB": _BY_ALIAS.get(_nk("vnc")),  # VNC protocol banner "RFB 003.008"
        "SMBD": _BY_ALIAS.get(_nk("smb")), "SAMBA": _BY_ALIAS.get(_nk("smb")),
        # MQTT brokers
        "MOSQUITTO": _BY_ALIAS.get(_nk("mqtt")), "EMQX": _BY_ALIAS.get(_nk("mqtt")),
        "HIVEMQ": _BY_ALIAS.get(_nk("mqtt")),
        # OT vendors
        "MODBUS": _BY_ALIAS.get(_nk("modbus")), "BACNET": _BY_ALIAS.get(_nk("bacnet")),
    }
    for k, v in tokens.items():
        if v is not None:
            _BANNER_TOKEN[_nk(k)] = v


def _web_record(port: int | None, transport: str) -> "_Proto | None":
    # web-server banner: prefer the port-derived HTTP/HTTPS verdict when known
    if port:
        by_port = _PROTOCOLS.get((int(port), str(transport).lower()))
        if by_port and by_port.category == "web":
            return by_port
    # default encrypted web
    return _PROTOCOLS.get((443, TCP))


def classify_service(name: str, port: int | None = None, transport: str = TCP) -> ProtocolInfo:
    """Classify a service by banner/service name (e.g. 'ssh', 'Microsoft-IIS').

    Uses the service name first (banner is the strongest signal), then the
    port. Tolerates version suffixes ('OpenSSH_9.0', 'nginx/1.24').
    """
    _build_banner_tokens()
    raw = str(name or "").strip()
    key = _nk(raw)
    if not key:
        return classify_port(port, transport) if port else _unknown(raw, port, transport)

    rec: _Proto | None = None
    if key in _BY_ALIAS:
        rec = _BY_ALIAS[key]
    elif key in _BANNER_TOKEN:
        rec = _BANNER_TOKEN[key]
    else:
        # token scan over the banner: 'SSH-2.0-OpenSSH_9.0', '220 ProFTPD 1.3.5'
        for token in re.split(r"[^A-Za-z0-9]+", raw.upper()):
            tk = _nk(token)
            if not tk:
                continue
            if tk in _WEB_SERVER_TOKENS:
                rec = _web_record(port, transport)
                break
            if tk in _BANNER_TOKEN:
                rec = _BANNER_TOKEN[tk]
                break
            if tk in _BY_ALIAS:
                rec = _BY_ALIAS[tk]
                break

    if rec is None:
        if port:
            return classify_port(port, transport)
        return _unknown(raw, port, transport)

    return ProtocolInfo(
        raw=raw, canonical=rec.canonical, port=port or rec.port,
        transport=transport if port else rec.transport,
        category=rec.category, status=rec.status, encrypted=rec.encrypted,
        exposure=rec.exposure, recognized=True, notes=rec.notes,
        risk_reason=_risk_reason(rec),
    )


def classify_endpoint(endpoint: str) -> ProtocolInfo:
    """Classify a ``host:port`` (or ``host:port/proto``) discovery endpoint."""
    ep = str(endpoint).strip()
    host, _, rest = ep.rpartition(":")
    if not host:  # bare port
        rest = ep
    port, _, proto = rest.partition("/")
    return classify_port(port, proto or TCP)


def _risk_reason(rec: _Proto) -> str:
    if rec.status == DISALLOWED:
        if not rec.encrypted:
            return f"{rec.canonical} is cleartext/unauthenticated — {rec.notes}"
        return f"{rec.canonical} is broken/deprecated — {rec.notes}"
    if rec.status == DEPRECATED:
        return f"{rec.canonical} is obsolete — {rec.notes}"
    if rec.exposure == OT_SAFETY:
        return f"{rec.canonical} is an OT/ICS service — observe passively, never probe safety systems"
    if rec.status == RESTRICTED and rec.exposure == INTERNAL:
        return f"{rec.canonical} should stay internal/segmented with strong auth"
    if rec.status == RESTRICTED:
        return f"{rec.canonical} requires additional controls — {rec.notes}"
    return ""


def risk_severity(info: ProtocolInfo, *, internet_facing: bool = False) -> str:
    """Deterministic severity for a finding, given whether the service is
    reachable from the internet. OT/ICS + cleartext drive the highest risk.
    """
    if not info.recognized:
        return "MEDIUM"
    if info.exposure == OT_SAFETY:
        return "HIGH" if internet_facing else "MEDIUM"
    if info.status == DISALLOWED:
        return "CRITICAL" if (internet_facing and not info.encrypted) else "HIGH"
    if info.status == DEPRECATED:
        return "MEDIUM"
    if info.status == RESTRICTED:
        if internet_facing and info.exposure == INTERNAL:
            return "HIGH"
        if internet_facing and not info.encrypted:
            return "HIGH"
        return "LOW" if info.encrypted else "MEDIUM"
    # ALLOWED
    if internet_facing and info.exposure == INTERNAL:
        return "MEDIUM"
    return "INFO"


def catalog() -> list[dict[str, Any]]:
    """The full protocol catalog (for APIs / dashboards)."""
    out: dict[str, dict[str, Any]] = {}
    for rec in _PROTOCOLS.values():
        if rec.canonical in out:
            continue
        out[rec.canonical] = ProtocolInfo(
            raw=rec.canonical, canonical=rec.canonical, port=rec.port,
            transport=rec.transport, category=rec.category, status=rec.status,
            encrypted=rec.encrypted, exposure=rec.exposure, recognized=True,
            notes=rec.notes, risk_reason=_risk_reason(rec),
        ).to_dict()
    return sorted(out.values(), key=lambda e: (e["category"], e["protocol"]))
