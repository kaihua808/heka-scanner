from enum import Enum
from typing import Optional, Dict, List


class RiskLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    def __str__(self):
        return self.value

    def __repr__(self):
        return f"RiskLevel.{self.name}"


class ServiceDetector:
    KNOWN_SERVICES: Dict[int, str] = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        119: "NNTP",
        123: "NTP",
        135: "MS-RPC",
        137: "NetBIOS-NS",
        138: "NetBIOS-DGM",
        139: "NetBIOS-SSN",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        515: "LPD",
        587: "SMTP-Submit",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS",
        1433: "MSSQL",
        1434: "MSSQL-UDP",
        1521: "Oracle",
        1723: "PPTP",
        2049: "NFS",
        2082: "cPanel",
        2083: "cPanel-SSL",
        2181: "ZooKeeper",
        3000: "Grafana",
        3306: "MySQL",
        3389: "RDP",
        4369: "Erlang",
        5060: "SIP",
        5432: "PostgreSQL",
        5672: "RabbitMQ",
        5900: "VNC",
        5985: "WinRM",
        5986: "WinRM-SSL",
        6379: "Redis",
        6443: "Kubernetes",
        6667: "IRC",
        8000: "HTTP-Alt",
        8008: "HTTP-Alt",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        8888: "HTTP-Alt",
        9000: "PHP-FPM",
        9090: "Prometheus",
        9200: "Elasticsearch",
        9300: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
        27018: "MongoDB",
        50000: "SAP",
    }

    HIGH_RISK_PORTS: List[int] = [
        21, 22, 23, 25, 110, 135, 137, 138, 139, 445,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017,
        11211, 5168
    ]

    MEDIUM_RISK_PORTS: List[int] = [
        80, 443, 465, 587, 993, 995, 1080, 1723, 2082, 2083,
        3000, 4369, 5060, 5672, 6443, 8000, 8008, 8080, 8443,
        8888, 9000, 9090, 9200, 9300
    ]

    def __init__(self):
        pass

    def detect(self, port: int) -> str:
        return self.KNOWN_SERVICES.get(port, "Unknown")

    def get_service_name(self, port: int) -> str:
        return self.detect(port)

    def is_known_service(self, port: int) -> bool:
        return port in self.KNOWN_SERVICES

    def get_risk_level(self, port: int) -> RiskLevel:
        if port in self.HIGH_RISK_PORTS:
            return RiskLevel.HIGH
        elif port in self.MEDIUM_RISK_PORTS:
            return RiskLevel.MEDIUM
        elif self.is_known_service(port):
            return RiskLevel.LOW
        else:
            return RiskLevel.NONE

    def get_risk_description(self, port: int) -> str:
        risk = self.get_risk_level(port)
        service = self.get_service_name(port)

        descriptions = {
            RiskLevel.HIGH: f"高危 - {service}服务存在已知安全风险",
            RiskLevel.MEDIUM: f"中危 - {service}服务可能存在配置问题",
            RiskLevel.LOW: f"低危 - {service}服务相对安全",
            RiskLevel.NONE: "未知端口，无风险评估数据"
        }

        return descriptions.get(risk, "未知")

    def get_all_services(self) -> Dict[int, str]:
        return self.KNOWN_SERVICES.copy()

    def get_services_by_category(self) -> Dict[str, List[int]]:
        return {
            "remote_access": [22, 23, 3389, 5900, 5985, 5986],
            "database": [1433, 1521, 3306, 5432, 6379, 27017, 11211, 9200],
            "web": [80, 443, 8000, 8008, 8080, 8443, 8888, 9000],
            "mail": [25, 110, 143, 465, 587, 993, 995],
            "file": [20, 21, 69, 139, 445, 515, 2049],
            "monitoring": [161, 162, 514, 9090, 9200],
            "messaging": [5060, 5672, 4369, 6667],
            "virtualization": [443, 6443, 2181],
        }

    def search_service(self, keyword: str) -> List[int]:
        keyword = keyword.lower()
        results = []

        for port, service in self.KNOWN_SERVICES.items():
            if keyword in service.lower():
                results.append(port)

        return sorted(results)

    @staticmethod
    def get_risk_color(risk_level: RiskLevel) -> str:
        colors = {
            RiskLevel.HIGH: "red",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.NONE: "white"
        }
        return colors.get(risk_level, "white")

    @staticmethod
    def get_risk_emoji(risk_level: RiskLevel) -> str:
        emojis = {
            RiskLevel.HIGH: "[HIGH]",
            RiskLevel.MEDIUM: "[MED]",
            RiskLevel.LOW: "[LOW]",
            RiskLevel.NONE: "[NONE]"
        }
        return emojis.get(risk_level, "[?]")

    def format_risk_info(self, port: int) -> str:
        risk = self.get_risk_level(port)
        emoji = self.get_risk_emoji(risk)
        service = self.get_service_name(port)
        description = self.get_risk_description(port)

        return f"{emoji} {service} ({description})"


def detect_service(port: int) -> str:
    detector = ServiceDetector()
    return detector.detect(port)


def get_risk_level(port: int) -> RiskLevel:
    detector = ServiceDetector()
    return detector.get_risk_level(port)


def get_port_info(port: int) -> dict:
    detector = ServiceDetector()
    risk = detector.get_risk_level(port)
    return {
        'port': port,
        'service': detector.detect(port),
        'risk_level': risk.value,
        'risk_emoji': detector.get_risk_emoji(risk),
        'description': detector.get_risk_description(port)
    }
