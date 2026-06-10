import asyncio
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List
from core.logger import Logger


class PortStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
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

    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'port': self.port,
            'status': self.status.value,
            'service': self.service,
            'response_time_ms': self.response_time_ms,
            'retry_count': self.retry_count,
            'error_message': self.error_message
        }


class AsyncPortScanner:
    def __init__(self, timeout: float = 1.0, logger: Logger = None):
        self.timeout = timeout
        self.logger = logger or Logger("AsyncPortScanner")
        self._windows_error_codes = {
            10035: 'WSAEWOULDBLOCK',
            10060: 'WSAETIMEDOUT',
            10061: 'WSAECONNREFUSED',
            10064: 'WSAEHOSTUNREACH'
        }

    async def scan(self, ip: str, port: int) -> PortResult:
        start_time = asyncio.get_event_loop().time()
        status = PortStatus.UNKNOWN
        error_message = ""

        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            status = PortStatus.OPEN
            
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
            return PortResult(
                ip=ip,
                port=port,
                status=status,
                response_time_ms=response_time
            )

        except asyncio.TimeoutError:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            status = PortStatus.FILTERED
            error_message = "连接超时"

        except ConnectionRefusedError:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            status = PortStatus.CLOSED

        except socket.gaierror:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            status = PortStatus.UNKNOWN
            error_message = "DNS解析失败"

        except OSError as e:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            error_code = getattr(e, 'errno', 0)
            error_str = str(e).lower()
            
            if error_code in (110, 10060, 10064) or 'timed out' in error_str or 'timeout' in error_str:
                status = PortStatus.FILTERED
            elif error_code in (111, 10061, 10056) or 'refused' in error_str:
                status = PortStatus.CLOSED
            elif error_code == 10035:
                status = PortStatus.FILTERED
                error_message = "连接进行中"
            else:
                status = PortStatus.UNKNOWN
            error_message = f"网络错误: {e}"

        except Exception as e:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            status = PortStatus.UNKNOWN
            error_message = str(e)
            self.logger.debug(f"{ip}:{port} - 异常: {e}")

        return PortResult(
            ip=ip,
            port=port,
            status=status,
            response_time_ms=response_time,
            error_message=error_message
        )

    async def scan_batch(self, ip: str, ports: List[int], 
                        progress_callback=None) -> List[PortResult]:
        tasks = [self.scan(ip, port) for port in ports]
        
        results = []
        completed = 0
        total = len(ports)
        
        for task in asyncio.as_completed(tasks):
            result = await task
            results.append(result)
            completed += 1
            
            if progress_callback:
                progress_callback(completed, total)
        
        return results

    def scan_sync(self, ip: str, ports: List[int], 
                  progress_callback=None) -> List[PortResult]:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                self.scan_batch(ip, ports, progress_callback)
            )
        finally:
            loop.close()
        
        return results
