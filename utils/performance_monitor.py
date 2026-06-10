import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
from collections import defaultdict
import statistics

from core.logger import Logger


@dataclass
class PerformanceBaseline:
    scan_type: str
    port_count: int
    ip_count: int
    avg_duration: float
    min_duration: float
    max_duration: float
    std_deviation: float
    sample_count: int
    last_updated: str


@dataclass
class SLAMetric:
    name: str
    target_time: float
    actual_time: float
    status: str
    threshold_percent: float = 10.0

    @property
    def meets_sla(self) -> bool:
        return self.actual_time <= self.target_time * (1 + self.threshold_percent / 100)

    @property
    def deviation_percent(self) -> float:
        if self.target_time == 0:
            return 0.0
        return ((self.actual_time - self.target_time) / self.target_time) * 100


@dataclass
class ScanPerformanceRecord:
    timestamp: str
    scan_type: str
    ip_count: int
    port_count: int
    duration: float
    open_ports: int
    threads_used: int
    bandwidth_avg: float = 0.0


class PerformanceBaselineManager:
    def __init__(self, history_file: str = "./data/performance_history.json", logger: Logger = None):
        self.history_file = Path(history_file)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logger or Logger("PerformanceBaseline")
        self._records: List[ScanPerformanceRecord] = []
        self._baselines: Dict[str, PerformanceBaseline] = {}
        self._load_history()

    def _load_history(self) -> None:
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for record in data.get('records', []):
                        self._records.append(ScanPerformanceRecord(**record))
                    for key, baseline in data.get('baselines', {}).items():
                        self._baselines[key] = PerformanceBaseline(**baseline)
                self.logger.info(f"已加载 {len(self._records)} 条历史性能记录")
            except Exception as e:
                self.logger.warning(f"加载历史记录失败: {e}")

    def _save_history(self) -> None:
        try:
            data = {
                'records': [asdict(r) for r in self._records],
                'baselines': {k: asdict(v) for k, v in self._baselines.items()},
                'last_updated': datetime.now().isoformat()
            }
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"保存历史记录失败: {e}")

    def record_scan(self, scan_type: str, ip_count: int, port_count: int,
                    duration: float, open_ports: int, threads_used: int,
                    bandwidth_avg: float = 0.0) -> None:
        record = ScanPerformanceRecord(
            timestamp=datetime.now().isoformat(),
            scan_type=scan_type,
            ip_count=ip_count,
            port_count=port_count,
            duration=duration,
            open_ports=open_ports,
            threads_used=threads_used,
            bandwidth_avg=bandwidth_avg
        )
        self._records.append(record)
        self._update_baseline(scan_type, ip_count, port_count)
        self._save_history()

    def _update_baseline(self, scan_type: str, ip_count: int, port_count: int) -> None:
        key = self._generate_key(scan_type, ip_count, port_count)
        relevant_records = [
            r for r in self._records
            if self._generate_key(r.scan_type, r.ip_count, r.port_count) == key
        ]

        if len(relevant_records) < 3:
            return

        durations = [r.duration for r in relevant_records]
        baseline = PerformanceBaseline(
            scan_type=scan_type,
            port_count=port_count,
            ip_count=ip_count,
            avg_duration=statistics.mean(durations),
            min_duration=min(durations),
            max_duration=max(durations),
            std_deviation=statistics.stdev(durations) if len(durations) > 1 else 0.0,
            sample_count=len(durations),
            last_updated=datetime.now().isoformat()
        )
        self._baselines[key] = baseline

    def _generate_key(self, scan_type: str, ip_count: int, port_count: int) -> str:
        return f"{scan_type}_{ip_count}_{port_count}"

    def get_baseline(self, scan_type: str = "default", ip_count: int = 1, port_count: int = 100) -> Optional[PerformanceBaseline]:
        key = self._generate_key(scan_type, ip_count, port_count)
        return self._baselines.get(key)

    def check_performance_anomaly(self, scan_type: str = "default",
                                  ip_count: int = 1, port_count: int = 100,
                                  current_duration: float = 0.0,
                                  alert_threshold_percent: float = 50.0) -> Dict[str, Any]:
        baseline = self.get_baseline(scan_type, ip_count, port_count)

        if not baseline:
            return {
                "has_baseline": False,
                "is_anomaly": False,
                "message": "无历史基线，无法判断"
            }

        deviation_percent = ((current_duration - baseline.avg_duration) / baseline.avg_duration) * 100 if baseline.avg_duration > 0 else 0

        is_anomaly = abs(deviation_percent) > alert_threshold_percent

        return {
            "has_baseline": True,
            "is_anomaly": is_anomaly,
            "baseline_avg": baseline.avg_duration,
            "current_duration": current_duration,
            "deviation_percent": deviation_percent,
            "alert_threshold": alert_threshold_percent,
            "message": f"性能偏差: {deviation_percent:+.1f}%" if is_anomaly else "性能正常"
        }

    def get_recent_records(self, limit: int = 10) -> List[ScanPerformanceRecord]:
        return sorted(self._records, key=lambda x: x.timestamp, reverse=True)[:limit]

    def clear_history(self) -> None:
        self._records.clear()
        self._baselines.clear()
        if self.history_file.exists():
            self.history_file.unlink()
        self.logger.info("历史性能记录已清除")


class SLAReporter:
    def __init__(self, target_time_per_port: float = 0.015, logger: Logger = None):
        self.target_time_per_port = target_time_per_port
        self.logger = logger or Logger("SLAReporter")
        self._scan_metrics: List[SLAMetric] = []

    def evaluate_scan(self, port_count: int, duration: float) -> SLAMetric:
        target_time = port_count * self.target_time_per_port

        metric = SLAMetric(
            name=f"Scan_{len(self._scan_metrics) + 1}",
            target_time=target_time,
            actual_time=duration,
            status="PASS" if duration <= target_time * 1.1 else "FAIL"
        )

        self._scan_metrics.append(metric)
        return metric

    def get_sla_summary(self) -> Dict[str, Any]:
        if not self._scan_metrics:
            return {
                "total_scans": 0,
                "pass_count": 0,
                "fail_count": 0,
                "pass_rate": 0.0,
                "avg_deviation": 0.0
            }

        pass_count = sum(1 for m in self._scan_metrics if m.meets_sla)
        fail_count = len(self._scan_metrics) - pass_count
        avg_deviation = statistics.mean([m.deviation_percent for m in self._scan_metrics]) if self._scan_metrics else 0.0

        return {
            "total_scans": len(self._scan_metrics),
            "pass_count": pass_count,
            "fail_count": fail_count,
            "pass_rate": (pass_count / len(self._scan_metrics)) * 100,
            "avg_deviation": avg_deviation,
            "target_time_per_port": self.target_time_per_port
        }

    def generate_sla_report(self, records: List[ScanPerformanceRecord],
                          baselines: Dict[str, PerformanceBaseline]) -> Dict[str, Any]:
        summary = self.get_sla_summary()

        detailed_metrics = []
        for record in records:
            metric = self.evaluate_scan(record.port_count * record.ip_count, record.duration)
            detailed_metrics.append({
                "timestamp": record.timestamp,
                "scan_type": record.scan_type,
                "duration": record.duration,
                "target_time": metric.target_time,
                "deviation_percent": metric.deviation_percent,
                "status": metric.status
            })

        return {
            "report_generated_at": datetime.now().isoformat(),
            "sla_summary": summary,
            "detailed_metrics": detailed_metrics[-20:],
            "baselines": {
                k: asdict(v) for k, v in baselines.items()
            }
        }

    def export_sla_report(self, file_path: str, records: List[ScanPerformanceRecord],
                         baselines: Dict[str, PerformanceBaseline]) -> bool:
        try:
            report = self.generate_sla_report(records, baselines)
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            self.logger.info(f"SLA报表已导出: {file_path}")
            return True

        except Exception as e:
            self.logger.error(f"导出SLA报表失败: {e}")
            return False

    def reset(self) -> None:
        self._scan_metrics.clear()


class PerformanceMonitor:
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger("PerformanceMonitor")
        self._start_time: Optional[float] = None
        self._scan_start_times: Dict[str, float] = {}

    def start_scan(self, scan_id: str = "default") -> None:
        self._scan_start_times[scan_id] = time.time()

    def end_scan(self, scan_id: str = "default") -> float:
        if scan_id not in self._scan_start_times:
            return 0.0
        duration = time.time() - self._scan_start_times[scan_id]
        del self._scan_start_times[scan_id]
        return duration

    def get_current_duration(self, scan_id: str = "default") -> float:
        if scan_id not in self._scan_start_times:
            return 0.0
        return time.time() - self._scan_start_times[scan_id]

    def estimate_remaining_time(self, completed: int, total: int, scan_id: str = "default") -> float:
        current_duration = self.get_current_duration(scan_id)
        if completed == 0:
            return 0.0
        avg_time_per_item = current_duration / completed
        remaining_items = total - completed
        return avg_time_per_item * remaining_items


def create_performance_monitor() -> PerformanceMonitor:
    return PerformanceMonitor()
