from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
from collections import defaultdict

from core.port_scanner import PortResult, PortStatus
from core.service_detector import ServiceDetector, RiskLevel


class ColorCode(Enum):
    RED = "red"
    YELLOW = "yellow"
    GREEN = "green"
    BLUE = "blue"
    WHITE = "white"
    GRAY = "gray"

    def __str__(self):
        return self.value


@dataclass
class RiskAnnotation:
    port: int
    service: str
    risk_level: RiskLevel
    color: ColorCode
    description: str
    recommendation: str = ""


@dataclass
class ConflictInfo:
    conflict_type: str
    ip: str
    port: Optional[int] = None
    details: str = ""
    conflict_with: Optional[str] = None


@dataclass
class HeatmapEntry:
    ip: str
    port: int
    risk_level: RiskLevel
    color: ColorCode
    weight: float


class RiskAnnotator:
    def __init__(self):
        self.service_detector = ServiceDetector()

        self._risk_config = {
            RiskLevel.HIGH: {
                "color": ColorCode.RED,
                "weight": 1.0,
                "requires_attention": True
            },
            RiskLevel.MEDIUM: {
                "color": ColorCode.YELLOW,
                "weight": 0.6,
                "requires_attention": True
            },
            RiskLevel.LOW: {
                "color": ColorCode.GREEN,
                "weight": 0.3,
                "requires_attention": False
            },
            RiskLevel.NONE: {
                "color": ColorCode.GRAY,
                "weight": 0.0,
                "requires_attention": False
            }
        }

        self._recommendations = {
            22: "SSH服务建议限制访问，仅允许受信任IP连接",
            23: "Telnet明文传输，建议更换为SSH",
            21: "FTP服务存在安全风险，建议使用SFTP替代",
            3389: "RDP服务易受攻击，建议限制访问并启用NLA",
            3306: "MySQL建议禁止公网访问，设置强密码",
            5432: "PostgreSQL建议禁止公网访问，设置强密码",
            1433: "MSSQL建议禁止公网访问，设置强密码",
            27017: "MongoDB建议启用认证，禁止公网访问",
            6379: "Redis建议启用认证，禁止公网访问",
            11211: "Memcached建议禁止公网访问",
            445: "SMB服务易受勒索软件攻击，建议禁用或限制",
        }

    def annotate_result(self, result: PortResult) -> RiskAnnotation:
        risk_level = self.service_detector.get_risk_level(result.port)
        service = result.service or self.service_detector.detect(result.port)
        config = self._risk_config.get(risk_level, self._risk_config[RiskLevel.NONE])

        description = self.service_detector.get_risk_description(result.port)
        recommendation = self._recommendations.get(result.port, "")

        return RiskAnnotation(
            port=result.port,
            service=service,
            risk_level=risk_level,
            color=config["color"],
            description=description,
            recommendation=recommendation
        )

    def annotate_results(self, results: List[PortResult]) -> List[RiskAnnotation]:
        return [self.annotate_result(r) for r in results if r.status == PortStatus.OPEN]

    def get_color_for_port(self, port: int) -> ColorCode:
        risk_level = self.service_detector.get_risk_level(port)
        config = self._risk_config.get(risk_level, self._risk_config[RiskLevel.NONE])
        return config["color"]

    def get_risk_weight(self, port: int) -> float:
        risk_level = self.service_detector.get_risk_level(port)
        config = self._risk_config.get(risk_level, self._risk_config[RiskLevel.NONE])
        return config["weight"]

    def get_high_risk_ports(self, results: List[PortResult]) -> List[PortResult]:
        return [
            r for r in results
            if r.status == PortStatus.OPEN
            and self.service_detector.get_risk_level(r.port) == RiskLevel.HIGH
        ]

    def get_medium_risk_ports(self, results: List[PortResult]) -> List[PortResult]:
        return [
            r for r in results
            if r.status == PortStatus.OPEN
            and self.service_detector.get_risk_level(r.port) == RiskLevel.MEDIUM
        ]

    def get_risk_summary(self, results: List[PortResult]) -> Dict[str, int]:
        summary = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }

        for r in results:
            if r.status == PortStatus.OPEN:
                risk = self.service_detector.get_risk_level(r.port)
                summary[risk.value] += 1

        return summary

    def calculate_network_risk_score(self, results: List[PortResult],
                                    weights: Optional[Dict[RiskLevel, float]] = None) -> float:
        if weights is None:
            weights = {
                RiskLevel.HIGH: 10.0,
                RiskLevel.MEDIUM: 5.0,
                RiskLevel.LOW: 1.0,
                RiskLevel.NONE: 0.0
            }

        total_score = 0.0
        for r in results:
            if r.status == PortStatus.OPEN:
                risk = self.service_detector.get_risk_level(r.port)
                total_score += weights.get(risk, 0.0)

        return total_score


class ConflictDetector:
    def __init__(self):
        self._ip_scan_times: Dict[str, float] = {}
        self._port_usage: Dict[int, Set[str]] = defaultdict(set)

    def detect_ip_conflicts(self, results: List[PortResult]) -> List[ConflictInfo]:
        conflicts = []

        ip_ports: Dict[str, List[int]] = defaultdict(list)
        for r in results:
            if r.status == PortStatus.OPEN:
                ip_ports[r.ip].append(r.port)

        scanned_ips = set(ip_ports.keys())
        duplicate_ips = scanned_ips.intersection(self._ip_scan_times.keys())

        for ip in duplicate_ips:
            conflicts.append(ConflictInfo(
                conflict_type="IP重复扫描",
                ip=ip,
                details=f"IP {ip} 在短时间内被多次扫描"
            ))

        for ip, ports in ip_ports.items():
            if len(ports) != len(set(ports)):
                port_counts: Dict[int, int] = defaultdict(int)
                for port in ports:
                    port_counts[port] += 1

                for port, count in port_counts.items():
                    if count > 1:
                        conflicts.append(ConflictInfo(
                            conflict_type="端口重复扫描",
                            ip=ip,
                            port=port,
                            details=f"端口 {port} 被扫描 {count} 次",
                            conflict_with=ip
                        ))

        return conflicts

    def detect_port_conflicts(self, results: List[PortResult]) -> List[ConflictInfo]:
        conflicts = []

        for r in results:
            if r.status == PortStatus.OPEN:
                self._port_usage[r.port].add(r.ip)

        for port, ips in self._port_usage.items():
            if len(ips) > 1:
                ips_list = sorted(list(ips))
                conflicts.append(ConflictInfo(
                    conflict_type="端口冲突",
                    ip=", ".join(ips_list),
                    port=port,
                    details=f"端口 {port} 在多个IP上开放: {', '.join(ips_list)}"
                ))

        return conflicts

    def detect_all_conflicts(self, results: List[PortResult]) -> List[ConflictInfo]:
        all_conflicts = []
        all_conflicts.extend(self.detect_ip_conflicts(results))
        all_conflicts.extend(self.detect_port_conflicts(results))
        return all_conflicts

    def mark_ip_scanned(self, ip: str, scan_time: float) -> None:
        self._ip_scan_times[ip] = scan_time

    def mark_port_used(self, port: int, ip: str) -> None:
        self._port_usage[port].add(ip)

    def clear_history(self) -> None:
        self._ip_scan_times.clear()
        self._port_usage.clear()


class HeatmapGenerator:
    def __init__(self, annotator: Optional[RiskAnnotator] = None):
        self.annotator = annotator or RiskAnnotator()

    def generate_heatmap(self, results: List[PortResult]) -> List[HeatmapEntry]:
        heatmap = []

        for r in results:
            if r.status == PortStatus.OPEN:
                risk_level = self.annotator.service_detector.get_risk_level(r.port)
                color = self.annotator.get_color_for_port(r.port)
                weight = self.annotator.get_risk_weight(r.port)

                heatmap.append(HeatmapEntry(
                    ip=r.ip,
                    port=r.port,
                    risk_level=risk_level,
                    color=color,
                    weight=weight
                ))

        return sorted(heatmap, key=lambda x: (-x.weight, x.port))

    def group_by_ip(self, heatmap: List[HeatmapEntry]) -> Dict[str, List[HeatmapEntry]]:
        grouped = defaultdict(list)
        for entry in heatmap:
            grouped[entry.ip].append(entry)
        return dict(grouped)

    def group_by_risk(self, heatmap: List[HeatmapEntry]) -> Dict[RiskLevel, List[HeatmapEntry]]:
        grouped = defaultdict(list)
        for entry in heatmap:
            grouped[entry.risk_level].append(entry)
        return dict(grouped)

    def get_heatmap_stats(self, heatmap: List[HeatmapEntry]) -> Dict[str, any]:
        if not heatmap:
            return {
                "total": 0,
                "by_risk": {},
                "by_color": {},
                "total_weight": 0.0
            }

        by_risk = defaultdict(int)
        by_color = defaultdict(int)
        total_weight = 0.0

        for entry in heatmap:
            by_risk[entry.risk_level] += 1
            by_color[entry.color] += 1
            total_weight += entry.weight

        return {
            "total": len(heatmap),
            "by_risk": dict(by_risk),
            "by_color": dict(by_color),
            "total_weight": total_weight
        }

    def render_text_heatmap(self, heatmap: List[HeatmapEntry],
                          max_entries: int = 20) -> str:
        if not heatmap:
            return "无热力数据"

        color_symbols = {
            ColorCode.RED: "[!]",
            ColorCode.YELLOW: "[~]",
            ColorCode.GREEN: "[.]",
            ColorCode.BLUE: "[i]",
            ColorCode.GRAY: "[-]"
        }

        lines = []
        entries_to_show = heatmap[:max_entries]

        for entry in entries_to_show:
            symbol = color_symbols.get(entry.color, "[-]")
            risk_str = entry.risk_level.value.upper()[:4]
            lines.append(f"{symbol} {entry.ip}:{entry.port} ({risk_str})")

        if len(heatmap) > max_entries:
            lines.append(f"... 还有 {len(heatmap) - max_entries} 个条目")

        return "\n".join(lines)


def create_risk_report(results: List[PortResult]) -> dict:
    annotator = RiskAnnotator()
    conflict_detector = ConflictDetector()
    heatmap_generator = HeatmapGenerator(annotator)

    annotations = annotator.annotate_results(results)
    conflicts = conflict_detector.detect_all_conflicts(results)
    heatmap = heatmap_generator.generate_heatmap(results)
    heatmap_stats = heatmap_generator.get_heatmap_stats(heatmap)
    risk_summary = annotator.get_risk_summary(results)
    risk_score = annotator.calculate_network_risk_score(results)

    return {
        "total_open_ports": len([r for r in results if r.status == PortStatus.OPEN]),
        "risk_summary": risk_summary,
        "risk_score": risk_score,
        "high_risk_ports": [
            {"ip": r.ip, "port": r.port, "service": r.service}
            for r in annotator.get_high_risk_ports(results)
        ],
        "conflicts": [
            {
                "type": c.conflict_type,
                "ip": c.ip,
                "port": c.port,
                "details": c.details
            }
            for c in conflicts
        ],
        "heatmap_stats": heatmap_stats
    }
