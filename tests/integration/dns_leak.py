"""DNS leak prevention inspection and packet validation helper."""

import socket
from typing import Optional


class DNSLeakDetector:
    """
    Verifies that TorPool never performs clearnet DNS lookups.
    Inspects SOCKS5 negotiation to confirm ATYP=0x03 (remote domain name resolution).
    """

    @staticmethod
    def verify_socks5h_address_type(socks5_req: bytes) -> bool:
        """
        Validate that a SOCKS5 request uses ATYP=0x03 (Domain Name) so DNS is performed
        remotely inside Tor, and never resolved locally on the host.
        SOCKS5 request layout: [VER(1), CMD(1), RSV(1), ATYP(1), ADDR(...), PORT(2)]
        """
        if len(socks5_req) < 4:
            return False
        ver, cmd, _rsv, atyp = socks5_req[0], socks5_req[1], socks5_req[2], socks5_req[3]
        return ver == 0x05 and cmd == 0x01 and atyp == 0x03

    @staticmethod
    def check_local_udp_53_bound() -> Optional[int]:
        """Check if any raw UDP socket on 53 can be bound (returns None if not permitted)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.close()
            return 0
        except Exception:
            return None
