#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from typing import List
from datetime import datetime

from core.config_loader import ConfigLoader
from core.logger import Logger
from core.ip_validator import IPValidator
from core.port_parser import PortParser
from scheduler import TaskScheduler, SchedulerConfig
from core.port_scanner import PortResult
from output.display import ResultDisplay, ScanTask, create_summary
from output.risk_assessment import RiskAnnotator, ConflictDetector, HeatmapGenerator, create_risk_report
from output.audit import AuditLogger, ResultExporter
from utils.bandwidth_monitor import BandwidthMonitor, AdaptiveBandwidthController
from utils.fault_tolerance import FaultToleranceManager
from utils.performance_monitor import PerformanceMonitor, PerformanceBaselineManager, SLAReporter


class PortScannerApp:
    def __init__(self, config_path: str = None):
        self.config = ConfigLoader(config_path)
        self.logger = Logger("PortScannerApp")

        self.ip_validator = IPValidator()
        self.port_parser = PortParser()
        self.result_display = ResultDisplay()
        self.risk_annotator = RiskAnnotator()
        self.conflict_detector = ConflictDetector()
        self.heatmap_generator = HeatmapGenerator(self.risk_annotator)
        self.audit_logger = AuditLogger()
        self.result_exporter = ResultExporter()

        self.bandwidth_monitor: BandwidthMonitor = None
        self.fault_tolerance: FaultToleranceManager = None
        self.performance_monitor = PerformanceMonitor(self.logger)
        self.baseline_manager = PerformanceBaselineManager(logger=self.logger)
        self.sla_reporter = SLAReporter(
            target_time_per_port=self.config.get("sla.target_time_per_port", 0.015),
            logger=self.logger
        )

        self._init_components()

    def _init_components(self):
        self.bandwidth_monitor = BandwidthMonitor(
            threshold_percent=self.config.get("bandwidth.threshold_percent", 30.0),
            check_interval=self.config.get("bandwidth.check_interval", 1.0)
        )

        self.fault_tolerance = FaultToleranceManager(
            timeout_manager=None,
            retry_manager=None,
            deadlock_detector=None,
            blacklist=None,
            logger=self.logger
        )

    def run(self, ip_or_cidr: str, port_str: str, output_path: str = None, output_format: str = "txt",
            show_progress: bool = True, enable_audit: bool = True):

        try:
            ips = self._validate_inputs(ip_or_cidr, port_str)
            if not ips:
                return False

            ports = self.port_parser.parse(port_str)
            if not ports:
                self.logger.error("未解析出有效端口")
                return False

            self.logger.info(f"目标IP: {ips}")
            self.logger.info(f"目标端口: {ports}")

            scheduler_config = SchedulerConfig(
                max_workers=self.config.get("scan.default_threads", 50),
                min_workers=self.config.get("scan.min_threads", 50),
                timeout=self.config.get("scan.timeout", 1.5),
                retry_count=self.config.get("scan.retry_count", 1),
                batch_size=self.config.get("scan.batch_size", 1000)
            )

            scheduler = TaskScheduler(scheduler_config)

            task = ScanTask(target=", ".join(ips), ports=port_str)
            self.result_display.display_header(task)

            if enable_audit:
                self.audit_logger.log_scan_start(ips, port_str)

            if show_progress:
                self.bandwidth_monitor.start()

            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.performance_monitor.start_scan(scan_id)

            results = scheduler.scan(
                targets=ips,
                ports=ports,
                progress_callback=self._progress_callback if show_progress else None,
                use_async=False
            )

            scan_duration = self.performance_monitor.end_scan(scan_id)

            if show_progress:
                self.bandwidth_monitor.stop()

            if not results:
                self.logger.warning("未获取到扫描结果")
                return False

            self._display_results(results)

            bandwidth_stats = self.bandwidth_monitor.get_stats() if show_progress else None
            risk_report = self._generate_risk_report(results)

            if output_path:
                self._export_results(results, output_path, output_format, enable_audit)

            if enable_audit:
                self.audit_logger.log_scan_complete(ips, port_str, results, scan_duration)

            task.end_time = datetime.now()
            task.total_time = scan_duration
            summary = create_summary(results, task.total_time)
            self.result_display.display_summary(summary)

            self._display_performance_report(len(ips), len(ports), scan_duration, results)

            return True

        except Exception as e:
            self.logger.error(f"扫描失败: {e}", exc_info=True)
            return False

    def _validate_inputs(self, ip_or_cidr: str, port_str: str) -> List[str]:
        try:
            ips = self.ip_validator.validate(ip_or_cidr)
            if not ips:
                self.logger.error("IP校验失败，未生成有效IP列表")
                return []

            for ip in ips:
                is_valid, error = self.ip_validator.is_valid(ip)
                if not is_valid:
                    self.audit_logger.log_compliance_violation(ip, error)
                    raise ValueError(f"合规校验失败: {error}")

            return ips

        except Exception as e:
            self.logger.error(f"输入校验失败: {e}")
            return []

    def _progress_callback(self, current: int, total: int):
        percentage = (current / total) * 100
        print(f"\r进度: [{current}/{total}] {percentage:.1f}%", end="")

        if current == total:
            print("\n")

    def _display_results(self, results: List[PortResult]):
        open_ports = [r for r in results if r.status and r.status.is_open()]
        self.result_display.display_results_table(open_ports)

        high_risk = self.risk_annotator.get_high_risk_ports(results)
        self.result_display.display_high_risk_ports(high_risk)

        heatmap = self.heatmap_generator.generate_heatmap(results)
        print("\n风险热力图:")
        print(self.heatmap_generator.render_text_heatmap(heatmap))

    def _generate_risk_report(self, results: List[PortResult]) -> dict:
        report = create_risk_report(results)
        print("\n风险报告:")
        print(f"开放端口总数: {report['total_open_ports']}")
        print(f"风险得分: {report['risk_score']}")
        print(f"高危端口数: {len(report['high_risk_ports'])}")

        if report['conflicts']:
            print("\n检测到冲突:")
            for c in report['conflicts']:
                print(f"  - {c['type']}: {c['details']}")

        return report

    def _display_performance_report(self, ip_count: int, port_count: int,
                                   duration: float, results: List[PortResult]) -> None:
        print("\n" + "=" * 70)
        print("性能报告")
        print("=" * 70)

        sla_metric = self.sla_reporter.evaluate_scan(port_count * ip_count, duration)
        print(f"扫描耗时: {duration:.2f} 秒")
        print(f"目标耗时: {sla_metric.target_time:.2f} 秒 (SLA基准)")
        print(f"SLA状态: {'通过' if sla_metric.meets_sla else '未达标'} (偏差: {sla_metric.deviation_percent:+.1f}%)")

        self.baseline_manager.record_scan(
            scan_type="default",
            ip_count=ip_count,
            port_count=port_count,
            duration=duration,
            open_ports=len([r for r in results if r.status and r.status.is_open()]),
            threads_used=self.config.get("scan.default_threads", 50),
            bandwidth_avg=0.0
        )

        anomaly_check = self.baseline_manager.check_performance_anomaly(
            ip_count=ip_count,
            port_count=port_count,
            current_duration=duration
        )

        if anomaly_check.get("has_baseline"):
            print(f"历史基线: {anomaly_check['baseline_avg']:.2f} 秒")
            print(f"性能偏差: {anomaly_check['deviation_percent']:+.1f}%")
            if anomaly_check.get("is_anomaly"):
                print("⚠️  警告: 检测到性能异常!")

        sla_summary = self.sla_reporter.get_sla_summary()
        print(f"SLA达标率: {sla_summary['pass_rate']:.1f}%")
        print("=" * 70)

    def _export_results(self, results: List[PortResult], output_path: str, output_format: str, enable_audit: bool):
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            success = self.result_exporter.export_results(
                results=results,
                file_path=str(output_path),
                format=output_format,
                include_metadata=True,
                sign=True
            )

            if success:
                self.logger.info(f"结果已导出到: {output_path}")

                if enable_audit:
                    self.audit_logger.log_export(str(output_path), output_format, len(results))
            else:
                self.logger.error(f"结果导出失败")

        except Exception as e:
            self.logger.error(f"导出异常: {e}")


def main():
    parser = argparse.ArgumentParser(description="端口扫描工具 - 合规版")
    parser.add_argument("-i", "--ip", required=True, help="目标IP或CIDR网段 (如 127.0.0.1 或 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", required=True, help="目标端口 (如 80, 1-100, common)")
    parser.add_argument("-o", "--output", help="结果输出文件路径")
    parser.add_argument("-f", "--format", choices=["txt", "csv", "json"], default="txt", help="输出格式 (默认: txt)")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--no-progress", action="store_true", help="不显示进度条")
    parser.add_argument("--no-audit", action="store_true", help="不记录审计日志")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")

    args = parser.parse_args()

    if args.no_color:
        import colorama
        colorama.init(strip=True)

    app = PortScannerApp(config_path=args.config)

    try:
        success = app.run(
            ip_or_cidr=args.ip,
            port_str=args.ports,
            output_path=args.output,
            output_format=args.format,
            show_progress=not args.no_progress,
            enable_audit=not args.no_audit
        )
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n程序异常: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
