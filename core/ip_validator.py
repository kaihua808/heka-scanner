import ipaddress
import socket
from typing import List, Tuple, Union
from core.exceptions import InvalidIPError, ComplianceViolationError
from core.logger import Logger


class IPValidator:
    ALLOWED_NETWORKS = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]

    PUBLIC_IP_RANGES = [
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.0.0.0/24'),
        ipaddress.ip_network('192.168.100.0/24'),
        ipaddress.ip_network('198.51.100.0/24'),
        ipaddress.ip_network('203.0.113.0/24'),
    ]

    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger("IPValidator")

    def validate(self, ip_input: str) -> List[str]:
        parsed_ips = self._parse_input(ip_input)
        validated_ips = []

        for ip in parsed_ips:
            self._validate_single_ip(ip)
            validated_ips.append(ip)

        return validated_ips

    def _parse_input(self, ip_input: str) -> List[str]:
        ip_input = ip_input.strip()

        if not ip_input:
            raise InvalidIPError(ip_input, "IP地址不能为空")

        if ip_input.lower() in ('localhost', '本机'):
            return ['127.0.0.1']

        if '/' in ip_input:
            return self._parse_cidr(ip_input)

        if '-' in ip_input:
            return self._parse_range(ip_input)

        return [self._normalize_ip(ip_input)]

    def _parse_cidr(self, cidr: str) -> List[str]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise InvalidIPError(cidr, f"无效的CIDR格式: {e}")

    def _parse_range(self, ip_range: str) -> List[str]:
        try:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()

            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)

            if start > end:
                raise InvalidIPError(ip_range, "起始IP不能大于结束IP")

            start_int = int(start)
            end_int = int(end)

            if end_int - start_int > 65535:
                raise InvalidIPError(ip_range, "IP范围过大，最多支持65536个IP")

            return [str(ipaddress.ip_address(i)) for i in range(start_int, end_int + 1)]

        except ValueError as e:
            raise InvalidIPError(ip_range, f"无效的IP范围格式: {e}")

    def _normalize_ip(self, ip_str: str) -> str:
        try:
            addr = ipaddress.ip_address(ip_str)
            return str(addr)
        except ValueError:
            raise InvalidIPError(ip_str, "无效的IP地址格式")

    def _validate_single_ip(self, ip: str) -> None:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError as e:
            raise InvalidIPError(ip, f"无效的IP地址: {e}")

        if not self._is_in_allowed_network(ip_obj):
            self._handle_compliance_violation(ip)

    def _is_in_allowed_network(self, ip: ipaddress.IPv4Address) -> bool:
        for network in self.ALLOWED_NETWORKS:
            if ip in network:
                return True
        return False

    def _is_public_ip(self, ip: ipaddress.IPv4Address) -> bool:
        for network in self.PUBLIC_IP_RANGES:
            if ip in network:
                return True

        if not self._is_in_allowed_network(ip):
            return True

        return False

    def _handle_compliance_violation(self, ip: str) -> None:
        reason = self._get_violation_reason(ip)

        self.logger.compliance_violation(ip, reason)

        raise ComplianceViolationError(ip, reason)

    def _get_violation_reason(self, ip: str) -> str:
        ip_obj = ipaddress.ip_address(ip)

        if self._is_public_ip(ip_obj):
            return "公网IP地址，不在允许的扫描范围内（仅允许127.0.0.0/8和192.168.0.0/16）"

        reason_parts = []
        for network in self.ALLOWED_NETWORKS:
            if ip_obj not in network:
                reason_parts.append(str(network))

        return f"IP不在允许的网段内。允许的网段: {', '.join(reason_parts)}"

    def is_valid(self, ip_input: str) -> Tuple[bool, str]:
        try:
            self.validate(ip_input)
            return True, ""
        except (InvalidIPError, ComplianceViolationError) as e:
            return False, str(e)

    def expand_network(self, cidr: str) -> List[str]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise InvalidIPError(cidr, f"无效的CIDR格式: {e}")

    def get_network_info(self, ip_input: str) -> dict:
        try:
            if '/' in ip_input:
                network = ipaddress.ip_network(ip_input, strict=False)
                return {
                    'type': 'network',
                    'network': str(network),
                    'netmask': str(network.netmask),
                    'broadcast': str(network.broadcast_address),
                    'num_hosts': network.num_addresses - 2,
                    'is_allowed': any(ip in network for ip in self.ALLOWED_NETWORKS)
                }
            else:
                ip_obj = ipaddress.ip_address(ip_input)
                return {
                    'type': 'single',
                    'ip': str(ip_obj),
                    'is_allowed': self._is_in_allowed_network(ip_obj),
                    'is_public': self._is_public_ip(ip_obj)
                }
        except ValueError as e:
            raise InvalidIPError(ip_input, f"无法解析IP信息: {e}")

    def check_host_reachability(self, ip: str) -> bool:
        try:
            socket.gethostbyname(ip)
            return True
        except socket.gaierror:
            return False

    def resolve_hostname(self, hostname: str) -> str:
        if hostname.lower() in ('localhost', '本机'):
            return '127.0.0.1'

        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            raise InvalidIPError(hostname, f"无法解析主机名: {hostname}")


def validate_ip_input(ip_input: str, logger: Logger = None) -> List[str]:
    validator = IPValidator(logger)
    return validator.validate(ip_input)


def is_valid_ip(ip_input: str) -> Tuple[bool, str]:
    validator = IPValidator()
    return validator.is_valid(ip_input)
