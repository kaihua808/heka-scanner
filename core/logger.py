import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional


class Logger:
    _instance = None
    _logger = None

    def __new__(cls, name: str = "PortScanner", config: Optional[dict] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, name: str = "PortScanner", config: Optional[dict] = None):
        if self._logger is None:
            self._setup_logger(name, config or self._get_default_config())

    def _get_default_config(self) -> dict:
        return {
            'level': 'INFO',
            'format': '%(asctime)s - %(levelname)s - %(message)s',
            'file': './logs/scanner.log',
            'console': True
        }

    def _setup_logger(self, name: str, config: dict) -> None:
        self._logger = logging.getLogger(name)
        self._logger.setLevel(getattr(logging, config.get('level', 'INFO')))
        
        self._logger.handlers.clear()
        
        formatter = logging.Formatter(config.get('format', '%(asctime)s - %(levelname)s - %(message)s'))
        
        if config.get('console', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self._logger.addHandler(console_handler)
        
        log_file = config.get('file')
        if log_file:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                Path(log_dir).mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)

    def info(self, msg: str) -> None:
        self._logger.info(msg)

    def warning(self, msg: str) -> None:
        self._logger.warning(msg)

    def error(self, msg: str, exc_info: bool = False) -> None:
        self._logger.error(msg, exc_info=exc_info)

    def debug(self, msg: str) -> None:
        self._logger.debug(msg)

    def critical(self, msg: str) -> None:
        self._logger.critical(msg)

    def exception(self, msg: str) -> None:
        self._logger.exception(msg)

    def compliance_violation(self, ip: str, reason: str) -> None:
        separator = "=" * 60
        violation_msg = f"""
{separator}
【合规违规警告】
违规时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
违规IP: {ip}
违规原因: {reason}
处理结果: 扫描已终止
{separator}
"""
        self._logger.critical(violation_msg)

    def scan_start(self, target: str, ports: str) -> None:
        self._logger.info(f"开始扫描 - 目标: {target}, 端口: {ports}")

    def scan_end(self, total_time: float, open_count: int, closed_count: int, filtered_count: int) -> None:
        self._logger.info(
            f"扫描完成 - 总耗时: {total_time:.2f}秒, "
            f"开放: {open_count}, 关闭: {closed_count}, 过滤: {filtered_count}"
        )

    def port_result(self, ip: str, port: int, status: str, service: str, time_ms: float) -> None:
        self._logger.debug(f"端口扫描结果 - {ip}:{port} - 状态: {status}, 服务: {service}, 耗时: {time_ms:.2f}ms")


def get_logger(name: str = "PortScanner", config: Optional[dict] = None) -> Logger:
    return Logger(name, config)
