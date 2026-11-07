"""Guest-only nft phase enforcement. Requested rules are never probe evidence."""
import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Final, Literal, assert_never

from backend_process import BackendError, Command, checked, require

Phase = Literal["PREPARE", "BUILD", "RUNTIME"]
TABLE: Final = "wakeio_t6p"
MAVEN: Final = "repo.maven.apache.org"
PUBLISHERS: Final = ("download.docker.com", "ports.ubuntu.com", "registry-1.docker.io",
                     "auth.docker.io", "production.cloudflare.docker.com",
                     "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com")


def resolve_public(host: str) -> tuple[str, ...]:
    addresses = tuple(sorted({row[4][0] for row in socket.getaddrinfo(
        host, 443, socket.AF_INET, socket.SOCK_STREAM)}))
    require(0 < len(addresses) <= 32, "publisher_address_count")
    require(all(ipaddress.ip_address(address).is_global for address in addresses), "publisher_private_address")
    return addresses


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    phase: Phase
    rules_sha256: str
    maven_addresses: tuple[str, ...]


class Network:
    """Mutable state represents one monotone, controller-owned firewall lifetime."""
    def __init__(self) -> None:
        self.phase: Phase = "PREPARE"
        self.maven = resolve_public(MAVEN)
        ipv6 = socket.getaddrinfo(MAVEN, 443, socket.AF_INET6, socket.SOCK_STREAM)
        require(bool(ipv6) and ipaddress.ip_address(ipv6[0][4][0]).is_global, "ipv6_witness_unavailable")
        self.ipv6 = ipv6[0][4][0]
        self.publishers = tuple(sorted({ip for host in PUBLISHERS for ip in resolve_public(host)}))
        self.installed = False

    def apply(self) -> NetworkObservation:
        import hashlib
        require(not self.installed, "network_replay")
        # Freeze exact publisher resolution before closing DNS egress, including the rootless daemon's resolver.
        with open("/etc/hosts", "a", encoding="ascii") as hosts:
            for host in (*PUBLISHERS, MAVEN):
                for address in resolve_public(host):
                    require(address in self.publishers or address in self.maven, "publisher_dns_changed")
                    hosts.write(address + " " + host + "\n")
        self._replace(create=True)
        self.installed = True
        observed = checked(Command(("/usr/sbin/nft", "-j", "list", "table", "inet", TABLE)))
        require(isinstance(json.loads(observed), dict), "network_observation")
        return NetworkObservation(self.phase, hashlib.sha256(observed).hexdigest(), self.maven)

    def transition(self, phase: Phase) -> NetworkObservation:
        import hashlib
        require(self.installed, "network_absent")
        match self.phase:
            case "PREPARE":
                require(phase == "BUILD", "network_transition")
            case "BUILD":
                require(phase == "RUNTIME", "network_transition")
            case "RUNTIME":
                raise BackendError("network_terminal")
            case unreachable:
                assert_never(unreachable)
        self.phase = phase
        self._replace(create=False)
        observed = checked(Command(("/usr/sbin/nft", "-j", "list", "table", "inet", TABLE)))
        return NetworkObservation(self.phase, hashlib.sha256(observed).hexdigest(), self.maven)

    def _replace(self, create: bool) -> None:
        match self.phase:
            case "PREPARE":
                root_allow = self.publishers
                user_allow = self.publishers
            case "BUILD":
                root_allow = ()
                user_allow = self.maven
            case "RUNTIME":
                root_allow = ()
                user_allow = ()
            case unreachable:
                assert_never(unreachable)
        script = "" if create else f"delete table inet {TABLE}\n"
        script += f"table inet {TABLE} {{\n"
        script += "chain output { type filter hook output priority -100; policy drop;\n"
        # Check UID before established state so closing PREPARE also closes its live connections.
        script += "meta skuid 10001 jump engine\n"
        script += "meta skuid 0 tcp sport 22 ct state established accept\n"
        script += "meta skuid 0 oifname lo accept\n"
        if root_allow:
            script += "meta skuid 0 ip daddr { " + ", ".join(root_allow) + " } tcp dport 443 accept\n"
        script += "}\nchain engine {\n"
        script += "ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, "
        script += "169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 } reject\n"
        script += "meta nfproto ipv6 reject\n"
        if user_allow:
            script += "ip daddr { " + ", ".join(user_allow) + " } tcp dport 443 accept\n"
        script += "reject\n}\n}\n"
        checked(Command(("/usr/sbin/nft", "--check", "-f", "-")), script.encode("ascii"))
        checked(Command(("/usr/sbin/nft", "-f", "-")), script.encode("ascii"))

    def cleanup(self) -> None:
        require(self.installed, "network_absent")
        checked(Command(("/usr/sbin/nft", "delete", "table", "inet", TABLE)))
        self.installed = False
