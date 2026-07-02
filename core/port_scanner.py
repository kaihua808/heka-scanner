import errno
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple
from core.exceptions import ScanTimeoutError
from core.logger import Logger


class PortStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_OR_FILTERED = "open_or_filtered"
    UNKNOWN = "unknown"

    def __str__(self):
        return self.value

    def is_open(self) -> bool:
        return self == PortStatus.OPEN


@dataclass
class PortResult:
    ip: str
    port: int
    status: PortStatus
    service: str = ""
    response_time_ms: float = 0.0
    retry_count: int = 0
    error_message: str = ""
    protocol: str = "tcp"
    scan_type: str = "tcp_connect"

    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'port': self.port,
            'status': self.status.value,
            'service': self.service,
            'response_time_ms': self.response_time_ms,
            'retry_count': self.retry_count,
            'error_message': self.error_message,
            'protocol': self.protocol,
            'scan_type': self.scan_type
        }


class PortScanner:
    def __init__(self, timeout: float = 3.0, retry_count: int = 2, logger: Logger = None):
        self.timeout = timeout
        self.retry_count = retry_count
        self.logger = logger or Logger("PortScanner")
        self._deadlock_threshold = 30

    def scan(self, ip: str, port: int) -> PortResult:
        start_time = time.time()
        retry = 0
        last_error = ""

        while retry <= self.retry_count:
            try:
                status, response_time = self._scan_single(ip, port)
                result = PortResult(
                    ip=ip,
                    port=port,
                    status=status,
                    response_time_ms=response_time,
                    retry_count=retry,
                    protocol="tcp",
                    scan_type="tcp_connect"
                )
                return result

            except socket.timeout:
                retry += 1
                last_error = "连接超时"
                if retry > self.retry_count:
                    self.logger.debug(f"{ip}:{port} - 重试{retry-1}次后超时")

            except socket.error as e:
                retry += 1
                last_error = f"Socket错误: {e}"
                if retry > self.retry_count:
                    self.logger.debug(f"{ip}:{port} - 重试{retry-1}次后失败: {e}")

            except Exception as e:
                last_error = f"未知错误: {e}"
                self.logger.debug(f"{ip}:{port} - 异常: {e}")
                break

        return PortResult(
            ip=ip,
            port=port,
            status=PortStatus.UNKNOWN,
            response_time_ms=(time.time() - start_time) * 1000,
            retry_count=retry,
            error_message=last_error,
            protocol="tcp",
            scan_type="tcp_connect"
        )

    def scan_udp(self, ip: str, port: int) -> PortResult:
        start_time = time.time()
        retry = 0
        last_error = ""

        while retry <= self.retry_count:
            try:
                status, response_time, error_message = self._scan_udp_single(ip, port)
                return PortResult(
                    ip=ip,
                    port=port,
                    status=status,
                    response_time_ms=response_time,
                    retry_count=retry,
                    error_message=error_message,
                    protocol="udp",
                    scan_type="udp"
                )

            except socket.timeout:
                retry += 1
                last_error = "UDP未收到响应"
                if retry > self.retry_count:
                    self.logger.debug(f"{ip}:{port}/udp - 重试{retry-1}次后未收到响应")

            except ConnectionRefusedError as e:
                return PortResult(
                    ip=ip,
                    port=port,
                    status=PortStatus.CLOSED,
                    response_time_ms=(time.time() - start_time) * 1000,
                    retry_count=retry,
                    error_message=f"UDP端口不可达: {e}",
                    protocol="udp",
                    scan_type="udp"
                )

            except OSError as e:
                error_code = getattr(e, "errno", 0)
                if error_code in (errno.ECONNREFUSED, 10061):
                    return PortResult(
                        ip=ip,
                        port=port,
                        status=PortStatus.CLOSED,
                        response_time_ms=(time.time() - start_time) * 1000,
                        retry_count=retry,
                        error_message=f"UDP端口不可达: {e}",
                        protocol="udp",
                        scan_type="udp"
                    )

                last_error = f"UDP Socket错误: {e}"
                self.logger.debug(f"{ip}:{port}/udp - 异常: {e}")
                return PortResult(
                    ip=ip,
                    port=port,
                    status=PortStatus.UNKNOWN,
                    response_time_ms=(time.time() - start_time) * 1000,
                    retry_count=retry,
                    error_message=last_error,
                    protocol="udp",
                    scan_type="udp"
                )

            except Exception as e:
                last_error = f"UDP未知错误: {e}"
                self.logger.debug(f"{ip}:{port}/udp - 异常: {e}")
                break

        return PortResult(
            ip=ip,
            port=port,
            status=PortStatus.OPEN_OR_FILTERED,
            response_time_ms=(time.time() - start_time) * 1000,
            retry_count=retry,
            error_message=last_error,
            protocol="udp",
            scan_type="udp"
        )

    def _scan_udp_single(self, ip: str, port: int) -> Tuple[PortStatus, float, str]:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((ip, port))
            sock.send(b"HEKA_UDP_PROBE")
            data = sock.recv(1024)
            response_time = (time.time() - start_time) * 1000
            sock.close()
            return PortStatus.OPEN, response_time, f"收到UDP响应({len(data)} bytes)"

        except socket.timeout:
            sock.close()
            raise

        except ConnectionRefusedError:
            sock.close()
            raise

        except OSError:
            sock.close()
            raise

        except Exception:
            sock.close()
            raise

    def _scan_single(self, ip: str, port: int) -> Tuple[PortStatus, float]:
        start_time = time.time()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((ip, port))

            if result == 0:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return PortStatus.OPEN, response_time

            elif result in (111, 10061):
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return PortStatus.CLOSED, response_time

            elif result in (110, 10060, 10064):
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return PortStatus.FILTERED, response_time

            elif result == 10035:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return PortStatus.FILTERED, response_time

            elif result == 10056:
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return PortStatus.CLOSED, response_time

            else:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                sock.close()
                return PortStatus.UNKNOWN, (time.time() - start_time) * 1000

        except socket.timeout:
            sock.close()
            raise socket.timeout()

        except socket.error as e:
            sock.close()
            error_code = getattr(e, 'errno', 0)
            if error_code in (111, 10061):
                return PortStatus.CLOSED, (time.time() - start_time) * 1000
            elif error_code in (110, 10060, 10064):
                return PortStatus.FILTERED, (time.time() - start_time) * 1000
            elif error_code == 10035:
                return PortStatus.FILTERED, (time.time() - start_time) * 1000
            elif error_code == 10056:
                return PortStatus.CLOSED, (time.time() - start_time) * 1000
            else:
                raise socket.error(e)

        except Exception as e:
            sock.close()
            raise

    def scan_with_banner(self, ip: str, port: int, timeout: Optional[float] = None) -> Tuple[PortStatus, str]:
        result = self.scan(ip, port)

        if result.status != PortStatus.OPEN:
            return result.status, ""

        banner = self._grab_banner(ip, port, timeout or self.timeout)
        return result.status, banner

    def _grab_banner(self, ip: str, port: int, timeout: float) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            try:
                sock.send(b"\r\n")
            except:
                pass

            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                banner = ""

            sock.close()
            return banner[:200]

        except:
            return ""

    def ping(self, ip: str, timeout: float = 1.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except:
            return False

    def check_port_available(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result != 0
        except:
            return True

    def set_deadlock_threshold(self, threshold: int) -> None:
        self._deadlock_threshold = threshold

    def get_deadlock_threshold(self) -> int:
        return self._deadlock_threshold


def scan_port(ip: str, port: int, timeout: float = 3.0) -> PortResult:
    scanner = PortScanner(timeout=timeout)
    return scanner.scan(ip, port)


def scan_ports_batch(ip: str, ports: list, timeout: float = 3.0) -> list:
    scanner = PortScanner(timeout=timeout)
    return [scanner.scan(ip, port) for port in ports]
