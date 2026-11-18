"""Cryptava — the CryptoScan host agent.

One small program installed on each bank server. Every cycle it reads the machine it
runs on and reports six views of it to the CryptoScan console:

==========  ===========================================================================
plane       what Cryptava reads (read-only, never key material)
==========  ===========================================================================
HBOM        DMI / sysfs: platform, BIOS, CPU (incl. AES-NI/SHA-NI), memory, disks,
            NICs, PCI devices (incl. crypto accelerators), TPM, dm-crypt volumes
SBOM        the package databases (dpkg / apk / rpm), Python dist-info, Java JARs
CBOM        crypto libraries on disk and loaded in running processes, certificates on
            disk and served by local listeners, TLS / SSH / OpenSSL configuration,
            SSH host keys, FIPS mode, negotiated TLS on every local listener
NBOM        listening sockets with their owning process, established outbound
            connections, the protocol each listener speaks (TLS / SSH / PostgreSQL)
VBOM        vendors derived from what was observed (hardware, OS, libraries, servers,
            certificate issuers) plus vendor-published lifecycle dates
TechBOM     derived by the platform from the hosts, services, databases, hardware
            and vendors above, plus the business system named in the agent config
==========  ===========================================================================

Design rules (the same ones the platform's own readers keep):

* **read, never change.** Files are opened read-only; the only programs Cryptava may
  run are in :data:`cryptava.util.ALLOWED_BINARIES`, with fixed argv and no shell;
* **no secrets leave the host.** Private-key files are never parsed; only public facts
  (algorithm, key size, fingerprints, validity dates) are reported;
* **every edge has evidence.** A relationship is only emitted together with the
  evidence record that establishes it — the platform refuses anything else;
* **a plane that could not be read says so.** It is reported ``FAILED``/``PARTIAL``
  with the reason, never as an empty estate.
"""

__version__ = "1.0.0"
AGENT_NAME = "cryptava"

__all__ = ["AGENT_NAME", "__version__"]
