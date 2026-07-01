from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from core.config_loader import ConfigLoader
from core.ip_validator import IPValidator
from core.logger import Logger
from core.port_parser import PortParser
from core.port_scanner import PortResult, PortStatus
from output.audit import AuditLogger
from scheduler import SchedulerConfig, TaskScheduler
from utils.bandwidth_monitor import BandwidthMonitor
from utils.fault_tolerance import FaultToleranceManager
from utils.performance_monitor import PerformanceBaselineManager, PerformanceMonitor, SLAReporter


class ScanService:
    def __init__(self):
        self.config = ConfigLoader()
        self.logger = Logger("ScanService")
        self.ip_validator = IPValidator()
        self.port_parser = PortParser()
        self.audit_logger = AuditLogger()
        self.performance_monitor = PerformanceMonitor()
        self.baseline_manager = PerformanceBaselineManager()
        self.sla_reporter = SLAReporter()
        self.bandwidth_monitor: Optional[BandwidthMonitor] = None
        self.fault_tolerance: Optional[FaultToleranceManager] = None

    def scan(self, ip_or_cidr: str, port_str: str = "1-1000",
             scan_mode: str = "full",
             progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        try:
            ips = self._validate_inputs(ip_or_cidr)
            if not ips:
                violation = getattr(self, "last_violation", None)
                return {"success": False, "error": "IP校验失败", "violation": violation}

            ports = self.port_parser.parse(port_str)
            if not ports:
                return {"success": False, "error": "端口解析失败"}

            mode_params = self._get_mode_parameters(scan_mode)
            self.logger.info(f"开始扫描({scan_mode}): {ips}, 端口: {ports}")
            self.audit_logger.log_scan_start(ips, port_str, scan_mode)

            scheduler_config = SchedulerConfig(
                max_workers=mode_params["max_workers"],
                min_workers=mode_params["min_workers"],
                timeout=mode_params["timeout"],
                retry_count=mode_params["retry_count"],
                batch_size=mode_params["batch_size"]
            )
            scheduler = TaskScheduler(scheduler_config)

            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.performance_monitor.start_scan(scan_id)

            results = scheduler.scan(
                targets=ips,
                ports=ports,
                progress_callback=progress_callback,
                use_async=False
            )

            duration = self.performance_monitor.end_scan(scan_id)

            self.logger.info(f"扫描结果数量: {len(results)}")
            if results:
                self.logger.info(f"第一个结果状态: {results[0].status}")

            if not results:
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "duration": duration,
                    "results": [],
                    "stats": self._generate_stats(results, duration)
                }

            self.audit_logger.log_scan_complete(ips, port_str, results, duration)
            self.baseline_manager.record_scan(
                scan_type="default",
                ip_count=len(ips),
                port_count=len(ports),
                duration=duration,
                open_ports=len([r for r in results if r.status == PortStatus.OPEN]),
                threads_used=mode_params["max_workers"]
            )

            return {
                "success": True,
                "scan_id": scan_id,
                "duration": duration,
                "results": [self._result_to_dict(r) for r in results],
                "stats": self._generate_stats(results, duration),
                "sla": self._generate_sla_info(len(ips), len(ports), duration)
            }

        except Exception as e:
            self.logger.error(f"扫描异常: {e}")
            return {"success": False, "error": str(e)}

    def _validate_inputs(self, ip_or_cidr: str) -> List[str]:
        try:
            ips = self.ip_validator.validate(ip_or_cidr)
            if not ips:
                return []

            for ip in ips:
                is_valid, error = self.ip_validator.is_valid(ip)
                if not is_valid:
                    self.audit_logger.log_compliance_violation(ip, error)
                    self.last_violation = {"ip": ip, "reason": error}
                    return []

            return ips

        except Exception as e:
            self.last_violation = {"ip": ip_or_cidr, "reason": str(e)}
            return []

    def get_last_violation(self):
        violation = getattr(self, "last_violation", None)
        self.last_violation = None
        return violation

    def _result_to_dict(self, result: PortResult) -> Dict[str, Any]:
        return {
            "ip": result.ip,
            "port": result.port,
            "status": result.status.value if result.status else "unknown",
            "service": result.service or "",
            "response_time": result.response_time_ms,
            "risk_level": self._get_risk_level(result.port)
        }

    def _get_risk_level(self, port: int) -> str:
        high_risk_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017}
        medium_risk_ports = {80, 443, 8080, 8443, 11211}
        if port in high_risk_ports:
            return "high"
        if port in medium_risk_ports:
            return "medium"
        return "low"

    def _generate_stats(self, results: List[PortResult], duration: float) -> Dict[str, Any]:
        return {
            "total": len(results),
            "open": len([r for r in results if r.status == PortStatus.OPEN]),
            "closed": len([r for r in results if r.status == PortStatus.CLOSED]),
            "filtered": len([r for r in results if r.status == PortStatus.FILTERED]),
            "duration": duration
        }

    def _generate_sla_info(self, ip_count: int, port_count: int, duration: float) -> Dict[str, Any]:
        total_items = ip_count * port_count
        sla_metric = self.sla_reporter.evaluate_scan(total_items, duration)
        summary = self.sla_reporter.get_sla_summary()

        return {
            "duration": duration,
            "target_duration": sla_metric.target_time,
            "status": "pass" if sla_metric.meets_sla else "fail",
            "deviation_percent": sla_metric.deviation_percent,
            "pass_rate": summary["pass_rate"]
        }

    def _get_mode_parameters(self, scan_mode: str) -> Dict[str, Any]:
        mode_configs = {
            "fast": {
                "max_workers": 500,
                "min_workers": 200,
                "timeout": 0.3,
                "retry_count": 0,
                "batch_size": 5000
            },
            "full": {
                "max_workers": 300,
                "min_workers": 100,
                "timeout": 1.0,
                "retry_count": 1,
                "batch_size": 2000
            },
            "syn": {
                "max_workers": 200,
                "min_workers": 50,
                "timeout": 1.5,
                "retry_count": 1,
                "batch_size": 1000
            },
            "udp": {
                "max_workers": 150,
                "min_workers": 30,
                "timeout": 2.0,
                "retry_count": 1,
                "batch_size": 1000
            },
            "comprehensive": {
                "max_workers": 400,
                "min_workers": 150,
                "timeout": 1.2,
                "retry_count": 1,
                "batch_size": 3000
            }
        }
        return mode_configs.get(scan_mode, mode_configs["full"])
