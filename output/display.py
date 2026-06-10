from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable
from core.port_scanner import PortResult, PortStatus
from core.service_detector import ServiceDetector, RiskLevel


@dataclass
class ScanTask:
    target: str
    ports: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_time: float = 0.0

    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()


@dataclass
class ScanSummary:
    total_ips: int = 0
    total_ports: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    unknown_count: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    scan_duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            'total_ips': self.total_ips,
            'total_ports': self.total_ports,
            'open_count': self.open_count,
            'closed_count': self.closed_count,
            'filtered_count': self.filtered_count,
            'unknown_count': self.unknown_count,
            'high_risk_count': self.high_risk_count,
            'medium_risk_count': self.medium_risk_count,
            'low_risk_count': self.low_risk_count,
            'scan_duration': self.scan_duration
        }


class ResultDisplay:
    def __init__(self, show_progress: bool = True):
        self.show_progress = show_progress
        self.service_detector = ServiceDetector()

    def display_header(self, task: ScanTask) -> None:
        print("\n" + "=" * 70)
        print("端口扫描结果")
        print("=" * 70)
        print(f"扫描目标: {task.target}")
        print(f"扫描端口: {task.ports}")
        print(f"开始时间: {task.start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    def display_summary(self, summary: ScanSummary) -> None:
        print(f"\n扫描耗时: {summary.scan_duration:.2f} 秒")
        print("-" * 70)
        print(f"扫描统计:")
        print(f"  IP数量: {summary.total_ips}")
        print(f"  端口总数: {summary.total_ports}")
        print(f"  开放端口: {summary.open_count}")
        print(f"  关闭端口: {summary.closed_count}")
        print(f"  过滤端口: {summary.filtered_count}")
        print(f"  未知端口: {summary.unknown_count}")
        print("-" * 70)
        print(f"风险统计:")
        print(f"  高危端口: {summary.high_risk_count}")
        print(f"  中危端口: {summary.medium_risk_count}")
        print(f"  低危端口: {summary.low_risk_count}")
        print("=" * 70)

    def display_results_table(self, results: List[PortResult],
                              sort_by: str = "port",
                              filter_status: Optional[PortStatus] = None) -> None:
        if not results:
            print("\n无扫描结果")
            return

        if filter_status:
            filtered_results = [r for r in results if r.status == filter_status]
        else:
            filtered_results = results

        if not filtered_results:
            print("\n无符合条件的扫描结果")
            return

        sorted_results = self._sort_results(filtered_results, sort_by)

        print(f"\n{'IP':<16} {'端口':<6} {'状态':<8} {'服务':<12} {'耗时(ms)':<10} {'风险':<6}")
        print("-" * 70)

        for result in sorted_results:
            service = result.service or self.service_detector.detect(result.port)
            risk = self.service_detector.get_risk_level(result.port)
            risk_str = f"[{risk.value.upper()[:4]}]"

            status_str = result.status.value.upper()
            time_str = f"{result.response_time_ms:.2f}"

            print(f"{result.ip:<16} {result.port:<6} {status_str:<8} {service:<12} {time_str:<10} {risk_str:<6}")

    def _sort_results(self, results: List[PortResult], sort_by: str) -> List[PortResult]:
        if sort_by == "ip":
            return sorted(results, key=lambda x: (x.ip, x.port))
        elif sort_by == "port":
            return sorted(results, key=lambda x: x.port)
        elif sort_by == "status":
            return sorted(results, key=lambda x: x.status.value)
        elif sort_by == "service":
            return sorted(results, key=lambda x: (x.service or "", x.port))
        elif sort_by == "time":
            return sorted(results, key=lambda x: x.response_time_ms)
        elif sort_by == "risk":
            risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.NONE: 3}
            return sorted(results, key=lambda x: (risk_order.get(self.service_detector.get_risk_level(x.port), 3), x.port))
        else:
            return results

    def display_open_ports(self, results: List[PortResult]) -> None:
        open_results = [r for r in results if r.status == PortStatus.OPEN]
        if open_results:
            print("\n开放端口详情:")
            self.display_results_table(open_results, sort_by="port")
        else:
            print("\n未发现开放端口")

    def display_high_risk_ports(self, results: List[PortResult]) -> None:
        high_risk_results = [
            r for r in results
            if r.status == PortStatus.OPEN and
            self.service_detector.get_risk_level(r.port) == RiskLevel.HIGH
        ]
        if high_risk_results:
            print("\n高危端口警告:")
            self.display_results_table(high_risk_results, sort_by="port")
        else:
            print("\n未发现高危端口")

    def display_compact(self, results: List[PortResult]) -> None:
        if not results:
            print("\n无扫描结果")
            return

        open_results = [r for r in results if r.status == PortStatus.OPEN]

        print("\n开放端口汇总:")
        if open_results:
            ports_by_ip = {}
            for r in open_results:
                if r.ip not in ports_by_ip:
                    ports_by_ip[r.ip] = []
                ports_by_ip[r.ip].append(r.port)

            for ip, ports in sorted(ports_by_ip.items()):
                ports_str = ",".join(str(p) for p in sorted(ports))
                print(f"  {ip}: {ports_str}")
        else:
            print("  无")

    def display_progress_bar(self, current: int, total: int, prefix: str = "进度") -> None:
        if not self.show_progress:
            return

        percent = 100 * current / total if total > 0 else 0
        bar_length = 40
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_length - filled)

        print(f"\r{prefix}: |{bar}| {percent:.1f}% ({current}/{total})", end="", flush=True)

        if current >= total:
            print()


class ProgressTracker:
    def __init__(self, total: int, callback: Optional[Callable] = None):
        self.total = total
        self.current = 0
        self.callback = callback
        self.start_time = datetime.now()

    def update(self, increment: int = 1) -> None:
        self.current += increment
        if self.callback:
            self.callback(self.current, self.total)

    def get_progress(self) -> tuple:
        return self.current, self.total

    def get_elapsed_time(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()

    def estimate_remaining_time(self) -> float:
        if self.current == 0:
            return 0
        elapsed = self.get_elapsed_time()
        if elapsed == 0:
            return 0
        rate = self.current / elapsed
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else 0


def create_summary(results: List[PortResult], scan_duration: float) -> ScanSummary:
    detector = ServiceDetector()

    summary = ScanSummary()
    summary.scan_duration = scan_duration
    summary.total_ports = len(results)

    unique_ips = set()
    for r in results:
        unique_ips.add(r.ip)
    summary.total_ips = len(unique_ips)

    for r in results:
        if r.status == PortStatus.OPEN:
            summary.open_count += 1
        elif r.status == PortStatus.CLOSED:
            summary.closed_count += 1
        elif r.status == PortStatus.FILTERED:
            summary.filtered_count += 1
        else:
            summary.unknown_count += 1

        if r.status == PortStatus.OPEN:
            risk = detector.get_risk_level(r.port)
            if risk == RiskLevel.HIGH:
                summary.high_risk_count += 1
            elif risk == RiskLevel.MEDIUM:
                summary.medium_risk_count += 1
            elif risk == RiskLevel.LOW:
                summary.low_risk_count += 1

    return summary
