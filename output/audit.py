import os
import csv
import json
import hashlib
import getpass
import platform
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from pathlib import Path

from core.logger import Logger
from core.port_scanner import PortResult, PortStatus


@dataclass
class AuditEntry:
    timestamp: str
    operator: str
    hostname: str
    action: str
    target: str
    result: str
    details: str = ""


@dataclass
class DigitalSignature:
    algorithm: str
    hash_value: str
    signed_at: str
    operator: str
    hostname: str


@dataclass
class AuditReport:
    report_id: str
    generated_at: str
    operator: str
    hostname: str
    platform: str
    scan_targets: List[str]
    scan_ports: str
    total_scanned: int
    open_ports: int
    closed_ports: int
    filtered_ports: int
    high_risk_ports: int
    medium_risk_ports: int
    low_risk_ports: int
    scan_duration: float
    signature: Optional[DigitalSignature] = None


class DigitalSigner:
    def __init__(self, algorithm: str = "SHA-256"):
        self.algorithm = algorithm

    def calculate_hash(self, content: str) -> str:
        if self.algorithm == "SHA-256":
            hasher = hashlib.sha256()
        elif self.algorithm == "SHA-512":
            hasher = hashlib.sha512()
        elif self.algorithm == "MD5":
            hasher = hashlib.md5()
        else:
            hasher = hashlib.sha256()

        hasher.update(content.encode('utf-8'))
        return hasher.hexdigest()

    def sign(self, content: str, operator: str = None, hostname: str = None) -> DigitalSignature:
        hash_value = self.calculate_hash(content)

        return DigitalSignature(
            algorithm=self.algorithm,
            hash_value=hash_value,
            signed_at=datetime.now().isoformat(),
            operator=operator or getpass.getuser(),
            hostname=hostname or platform.node()
        )

    def verify(self, content: str, signature: DigitalSignature) -> bool:
        calculated_hash = self.calculate_hash(content)
        return calculated_hash == signature.hash_value


class AuditLogger:
    def __init__(self,
                 log_dir: str = "logs",
                 operator: str = None,
                 logger: Logger = None):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.operator = operator or getpass.getuser()
        self.hostname = platform.node()
        self.platform_name = platform.platform()

        self.signer = DigitalSigner()
        self.logger = logger or Logger("AuditLogger")

        self._audit_entries: List[AuditEntry] = []

    def log_action(self,
                   action: str,
                   target: str,
                   result: str,
                   details: str = "") -> AuditEntry:
        entry = AuditEntry(
            timestamp=datetime.now().isoformat(),
            operator=self.operator,
            hostname=self.hostname,
            action=action,
            target=target,
            result=result,
            details=details
        )

        self._audit_entries.append(entry)
        self.logger.info(f"审计: {action} - {target} - {result}")

        return entry

    def log_scan_start(self, targets: List[str], ports: str, scan_mode: str = "full") -> AuditEntry:
        return self.log_action(
            action="SCAN_START",
            target=", ".join(targets),
            result="INITIATED",
            details=f"Ports: {ports}, Mode: {scan_mode}"
        )

    def log_scan_complete(self,
                         targets: List[str],
                         ports: str,
                         results: List[PortResult],
                         duration: float) -> AuditEntry:
        open_count = len([r for r in results if r.status == PortStatus.OPEN])
        closed_count = len([r for r in results if r.status == PortStatus.CLOSED])
        filtered_count = len([r for r in results if r.status == PortStatus.FILTERED])

        details = (
            f"Duration: {duration:.2f}s | "
            f"Open: {open_count} | "
            f"Closed: {closed_count} | "
            f"Filtered: {filtered_count}"
        )

        return self.log_action(
            action="SCAN_COMPLETE",
            target=", ".join(targets),
            result="SUCCESS" if open_count > 0 else "NO_OPEN_PORTS",
            details=details
        )

    def log_compliance_violation(self, ip: str, reason: str) -> AuditEntry:
        return self.log_action(
            action="COMPLIANCE_VIOLATION",
            target=ip,
            result="BLOCKED",
            details=reason
        )

    def log_export(self, file_path: str, format: str, record_count: int) -> AuditEntry:
        return self.log_action(
            action="EXPORT",
            target=file_path,
            result="SUCCESS",
            details=f"Format: {format}, Records: {record_count}"
        )

    def get_audit_trail(self) -> List[AuditEntry]:
        return self._audit_entries.copy()

    def export_audit_log(self,
                        file_path: str,
                        format: str = "txt",
                        include_signature: bool = True) -> bool:
        try:
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)

            content = self._generate_audit_content(format)

            signature = None
            if include_signature:
                signature = self.signer.sign(content, self.operator, self.hostname)
                content = self._add_signature_to_content(content, signature)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            self.log_export(str(file_path), format, len(self._audit_entries))
            self.logger.info(f"审计日志已导出: {file_path}")

            return True

        except Exception as e:
            self.logger.error(f"导出审计日志失败: {e}")
            return False

    def _generate_audit_content(self, format: str) -> str:
        if format == "txt":
            return self._generate_txt_audit()
        elif format == "csv":
            return self._generate_csv_audit()
        elif format == "json":
            return self._generate_json_audit()
        return self._generate_txt_audit()

    def _generate_txt_audit(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("端口扫描审计日志")
        lines.append("=" * 70)
        lines.append(f"生成时间: {datetime.now().isoformat()}")
        lines.append(f"操作员: {self.operator}")
        lines.append(f"主机名: {self.hostname}")
        lines.append(f"平台: {self.platform_name}")
        lines.append("=" * 70)
        lines.append("")

        for i, entry in enumerate(self._audit_entries, 1):
            lines.append(f"[{i}] {entry.timestamp}")
            lines.append(f"  操作: {entry.action}")
            lines.append(f"  目标: {entry.target}")
            lines.append(f"  结果: {entry.result}")
            if entry.details:
                lines.append(f"  详情: {entry.details}")
            lines.append("-" * 40)

        lines.append("")
        lines.append(f"总计记录: {len(self._audit_entries)}")

        return "\n".join(lines)

    def _generate_csv_audit(self) -> str:
        lines = []
        lines.append("Timestamp,Operator,Hostname,Action,Target,Result,Details")

        for entry in self._audit_entries:
            lines.append(
                f'"{entry.timestamp}",'
                f'"{entry.operator}",'
                f'"{entry.hostname}",'
                f'"{entry.action}",'
                f'"{entry.target}",'
                f'"{entry.result}",'
                f'"{entry.details}"'
            )

        return "\n".join(lines)

    def _generate_json_audit(self) -> str:
        data = {
            "audit_log": {
                "generated_at": datetime.now().isoformat(),
                "operator": self.operator,
                "hostname": self.hostname,
                "platform": self.platform_name,
                "total_entries": len(self._audit_entries),
                "entries": [
                    {
                        "timestamp": e.timestamp,
                        "operator": e.operator,
                        "hostname": e.hostname,
                        "action": e.action,
                        "target": e.target,
                        "result": e.result,
                        "details": e.details
                    }
                    for e in self._audit_entries
                ]
            }
        }

        return json.dumps(data, indent=2, ensure_ascii=False)

    def _add_signature_to_content(self, content: str, signature: DigitalSignature) -> str:
        sig_section = []
        sig_section.append("")
        sig_section.append("=" * 70)
        sig_section.append("数字签名")
        sig_section.append("=" * 70)
        sig_section.append(f"算法: {signature.algorithm}")
        sig_section.append(f"哈希值: {signature.hash_value}")
        sig_section.append(f"签名时间: {signature.signed_at}")
        sig_section.append(f"签名人: {signature.operator}")
        sig_section.append(f"主机名: {signature.hostname}")
        sig_section.append("=" * 70)

        return content + "\n".join(sig_section)

    def verify_file_integrity(self, file_path: str) -> tuple:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            lines = content.split("\n")

            sig_start = -1
            for i, line in enumerate(lines):
                if line == "数字签名" or line == "Digital Signature":
                    sig_start = i
                    break

            if sig_start == -1:
                return False, "未找到数字签名"

            content_part = "\n".join(lines[:sig_start - 1])
            sig_part = "\n".join(lines[sig_start:])

            hash_value = None
            operator = None
            hostname = None

            for line in lines[sig_start:]:
                if "哈希值:" in line:
                    hash_value = line.split(":", 1)[1].strip()
                elif "签名人:" in line:
                    operator = line.split(":", 1)[1].strip()
                elif "主机名:" in line and "平台:" not in line:
                    hostname = line.split(":", 1)[1].strip()

            if not hash_value:
                return False, "签名哈希值不完整"

            signature = DigitalSignature(
                algorithm="SHA-256",
                hash_value=hash_value,
                signed_at="",
                operator=operator or "",
                hostname=hostname or ""
            )

            calculated_hash = self.signer.calculate_hash(content_part)
            is_valid = calculated_hash == hash_value

            if is_valid:
                return True, "签名验证通过"
            else:
                return False, "签名验证失败 - 文件可能被篡改"

        except Exception as e:
            return False, f"验证异常: {str(e)}"


class ResultExporter:
    def __init__(self,
                 output_dir: str = "output",
                 operator: str = None,
                 logger: Logger = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.operator = operator or getpass.getuser()
        self.hostname = platform.node()

        self.signer = DigitalSigner()
        self.logger = logger or Logger("ResultExporter")

    def export_results(self,
                      results: List[PortResult],
                      file_path: str,
                      format: str = "txt",
                      include_metadata: bool = True,
                      sign: bool = True) -> bool:
        try:
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)

            if format == "txt":
                content = self._export_txt(results, include_metadata)
                if sign:
                    signature = self.signer.sign(content, self.operator, self.hostname)
                    content = self._add_signature(content, signature)
            elif format == "csv":
                content = self._export_csv(results, include_metadata)
                if sign:
                    signature = self.signer.sign(content, self.operator, self.hostname)
                    content = self._add_signature(content, signature)
            elif format == "json":
                content = self._export_json(results, include_metadata)
                if sign:
                    signature = self.signer.sign(content, self.operator, self.hostname)
                    content = self._add_json_signature(content, signature)
            else:
                content = self._export_txt(results, include_metadata)
                if sign:
                    signature = self.signer.sign(content, self.operator, self.hostname)
                    content = self._add_signature(content, signature)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            self.logger.info(f"结果已导出: {file_path}")
            return True

        except Exception as e:
            self.logger.error(f"导出结果失败: {e}")
            return False

    def _export_txt(self, results: List[PortResult], include_metadata: bool) -> str:
        lines = []

        if include_metadata:
            lines.append("=" * 70)
            lines.append("端口扫描结果")
            lines.append("=" * 70)
            lines.append(f"导出时间: {datetime.now().isoformat()}")
            lines.append(f"操作员: {self.operator}")
            lines.append(f"主机名: {self.hostname}")
            lines.append("=" * 70)
            lines.append("")

        lines.append(f"{'IP':<20} {'端口':<8} {'状态':<10} {'服务':<15} {'耗时(ms)':<10}")
        lines.append("-" * 70)

        for r in results:
            status_str = r.status.value
            service_str = r.service or "-"
            time_str = f"{r.response_time_ms:.2f}" if r.response_time_ms else "-"

            lines.append(f"{r.ip:<20} {r.port:<8} {status_str:<10} {service_str:<15} {time_str:<10}")

        lines.append("")
        lines.append(f"总计: {len(results)} 条记录")

        open_count = len([r for r in results if r.status == PortStatus.OPEN])
        closed_count = len([r for r in results if r.status == PortStatus.CLOSED])
        filtered_count = len([r for r in results if r.status == PortStatus.FILTERED])

        lines.append(f"开放: {open_count} | 关闭: {closed_count} | 过滤: {filtered_count}")

        return "\n".join(lines)

    def _export_csv(self, results: List[PortResult], include_metadata: bool) -> str:
        lines = []

        if include_metadata:
            lines.append(f"# 导出时间: {datetime.now().isoformat()}")
            lines.append(f"# 操作员: {self.operator}")
            lines.append(f"# 主机名: {self.hostname}")
            lines.append("")

        lines.append("IP,Port,Status,Service,ResponseTime(ms)")

        for r in results:
            time_str = f"{r.response_time_ms:.2f}" if r.response_time_ms else ""
            lines.append(
                f"{r.ip},"
                f"{r.port},"
                f"{r.status.value},"
                f"{r.service or ''},"
                f"{time_str}"
            )

        return "\n".join(lines)

    def _export_json(self, results: List[PortResult], include_metadata: bool) -> str:
        data = {
            "export_info": {
                "exported_at": datetime.now().isoformat(),
                "operator": self.operator,
                "hostname": self.hostname
            } if include_metadata else {},
            "results": [
                {
                    "ip": r.ip,
                    "port": r.port,
                    "status": r.status.value,
                    "service": r.service,
                    "response_time_ms": r.response_time_ms
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "open": len([r for r in results if r.status == PortStatus.OPEN]),
                "closed": len([r for r in results if r.status == PortStatus.CLOSED]),
                "filtered": len([r for r in results if r.status == PortStatus.FILTERED])
            }
        }

        return json.dumps(data, indent=2, ensure_ascii=False)

    def _add_signature(self, content: str, signature: DigitalSignature) -> str:
        sig_section = []
        sig_section.append("")
        sig_section.append("=" * 70)
        sig_section.append("数字签名")
        sig_section.append("=" * 70)
        sig_section.append(f"算法: {signature.algorithm}")
        sig_section.append(f"哈希值: {signature.hash_value}")
        sig_section.append(f"签名时间: {signature.signed_at}")
        sig_section.append(f"签名人: {signature.operator}")
        sig_section.append(f"主机名: {signature.hostname}")
        sig_section.append("=" * 70)

        return content + "\n".join(sig_section)

    def _add_json_signature(self, json_content: str, signature: DigitalSignature) -> str:
        data = json.loads(json_content)
        data["signature"] = {
            "algorithm": signature.algorithm,
            "hash_value": signature.hash_value,
            "signed_at": signature.signed_at,
            "operator": signature.operator,
            "hostname": signature.hostname
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def verify_export_integrity(self, file_path: str) -> tuple:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if content.strip().startswith('{'):
                return self._verify_json_integrity(content)
            else:
                return self._verify_text_integrity(content)

        except Exception as e:
            return False, f"验证异常: {str(e)}"

    def _verify_json_integrity(self, content: str) -> tuple:
        try:
            data = json.loads(content)

            if "signature" not in data:
                return False, "未找到数字签名"

            sig = data["signature"]
            hash_value = sig.get("hash_value")

            if not hash_value:
                return False, "签名哈希值不完整"

            data_without_sig = {k: v for k, v in data.items() if k != "signature"}
            content_part = json.dumps(data_without_sig, indent=2, sort_keys=True)

            calculated_hash = self.signer.calculate_hash(content_part)
            is_valid = calculated_hash == hash_value

            if is_valid:
                return True, "签名验证通过"
            else:
                return False, "签名验证失败 - 文件可能被篡改"

        except json.JSONDecodeError:
            return False, "JSON格式解析失败"
        except Exception as e:
            return False, f"验证异常: {str(e)}"

    def _verify_text_integrity(self, content: str) -> tuple:
        lines = content.split("\n")

        sig_start = -1
        for i, line in enumerate(lines):
            if line == "数字签名":
                sig_start = i
                break

        if sig_start == -1:
            return False, "未找到数字签名"

        content_part = "\n".join(lines[:sig_start - 1])

        hash_value = None
        for line in lines[sig_start:]:
            if "哈希值:" in line:
                hash_value = line.split(":", 1)[1].strip()
                break

        if not hash_value:
            return False, "签名哈希值不完整"

        calculated_hash = self.signer.calculate_hash(content_part)
        is_valid = calculated_hash == hash_value

        if is_valid:
            return True, "签名验证通过"
        else:
            return False, "签名验证失败 - 文件可能被篡改"


def generate_sla_report(scan_history: List[dict],
                       target_duration: float = 15.0) -> dict:
    if not scan_history:
        return {
            "total_scans": 0,
            "avg_duration": 0.0,
            "min_duration": 0.0,
            "max_duration": 0.0,
            "compliance_rate": 0.0,
            "target_duration": target_duration,
            "met_sla_count": 0,
            "failed_sla_count": 0
        }

    durations = [s.get("duration", 0) for s in scan_history]
    avg_duration = sum(durations) / len(durations)
    min_duration = min(durations)
    max_duration = max(durations)

    met_sla = len([d for d in durations if d <= target_duration])
    compliance_rate = (met_sla / len(durations)) * 100 if durations else 0

    return {
        "total_scans": len(scan_history),
        "avg_duration": avg_duration,
        "min_duration": min_duration,
        "max_duration": max_duration,
        "compliance_rate": compliance_rate,
        "target_duration": target_duration,
        "met_sla_count": met_sla,
        "failed_sla_count": len(scan_history) - met_sla
    }
