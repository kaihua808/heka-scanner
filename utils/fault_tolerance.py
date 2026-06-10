import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable, List, Set, Dict, Any
from enum import Enum
from collections import defaultdict

from core.logger import Logger
from core.port_scanner import PortResult, PortStatus


class TimeoutType(Enum):
    NETWORK = "network"
    SERVICE = "service"
    UNKNOWN = "unknown"


class DeadlockType(Enum):
    THREAD = "thread"
    RESOURCE = "resource"
    NONE = "none"


@dataclass
class RetryResult:
    success: bool
    attempts: int
    final_status: PortStatus
    timeout_type: TimeoutType = TimeoutType.UNKNOWN
    error_message: str = ""


@dataclass
class DeadlockInfo:
    thread_id: int
    thread_name: str
    detected_at: datetime
    wait_time: float
    task_info: str = ""


class TimeoutManager:
    def __init__(self,
                 default_timeout: float = 3.0,
                 max_timeout: float = 30.0,
                 logger: Logger = None):
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.logger = logger or Logger("TimeoutManager")

        self._timeouts: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get_timeout(self, ip: str, port: int) -> float:
        key = f"{ip}:{port}"
        with self._lock:
            return self._timeouts.get(key, self.default_timeout)

    def set_timeout(self, ip: str, port: int, timeout: float) -> None:
        key = f"{ip}:{port}"
        with self._lock:
            self._timeouts[key] = min(timeout, self.max_timeout)

    def get_or_create_timeout(self, ip: str, port: int,
                              base_timeout: Optional[float] = None) -> float:
        timeout = self.get_timeout(ip, port)
        if timeout == self.default_timeout and base_timeout:
            return base_timeout
        return timeout

    def remove_timeout(self, ip: str, port: int) -> None:
        key = f"{ip}:{port}"
        with self._lock:
            self._timeouts.pop(key, None)

    def clear_all(self) -> None:
        with self._lock:
            self._timeouts.clear()


class RetryManager:
    def __init__(self,
                 max_retries: int = 2,
                 network_retry_delay: float = 0.5,
                 service_retry_delay: float = 1.0,
                 logger: Logger = None):
        self.max_retries = max_retries
        self.network_retry_delay = network_retry_delay
        self.service_retry_delay = service_retry_delay
        self.logger = logger or Logger("RetryManager")

        self._retry_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def should_retry(self, ip: str, port: int) -> bool:
        key = f"{ip}:{port}"
        with self._lock:
            return self._retry_counts[key] < self.max_retries

    def get_retry_delay(self, timeout_type: TimeoutType) -> float:
        if timeout_type == TimeoutType.NETWORK:
            return self.network_retry_delay
        elif timeout_type == TimeoutType.SERVICE:
            return self.service_retry_delay
        return 0.1

    def record_attempt(self, ip: str, port: int) -> None:
        key = f"{ip}:{port}"
        with self._lock:
            self._retry_counts[key] += 1

    def get_attempt_count(self, ip: str, port: int) -> int:
        key = f"{ip}:{port}"
        with self._lock:
            return self._retry_counts[key]

    def reset_attempts(self, ip: str, port: int) -> None:
        key = f"{ip}:{port}"
        with self._lock:
            self._retry_counts[key] = 0

    def clear_all(self) -> None:
        with self._lock:
            self._retry_counts.clear()

    def classify_timeout(self, result: PortResult,
                        previous_results: Optional[List[PortResult]] = None) -> TimeoutType:
        if result.error_message:
            error_lower = result.error_message.lower()
            if "timeout" in error_lower or "timed out" in error_lower:
                if "connection" in error_lower or "network" in error_lower:
                    return TimeoutType.NETWORK
                return TimeoutType.SERVICE

        if result.response_time_ms >= 2000:
            return TimeoutType.NETWORK

        return TimeoutType.UNKNOWN


class DeadlockDetector:
    def __init__(self,
                 threshold_seconds: float = 30.0,
                 check_interval: float = 5.0,
                 logger: Logger = None):
        self.threshold_seconds = threshold_seconds
        self.check_interval = check_interval
        self.logger = logger or Logger("DeadlockDetector")

        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._is_running = False

        self._thread_last_activity: Dict[int, float] = {}
        self._deadlock_callbacks: List[Callable[[DeadlockInfo], None]] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._is_running:
            return

        self._stop_flag.clear()
        self._is_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self.logger.info("死锁检测已启动")

    def stop(self) -> None:
        if not self._is_running:
            return

        self._stop_flag.set()
        self._is_running = False

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

        self.logger.info("死锁检测已停止")

    def register_thread(self, thread_id: Optional[int] = None) -> None:
        tid = thread_id or threading.current_thread().ident
        with self._lock:
            self._thread_last_activity[tid] = time.time()

    def update_thread_activity(self, thread_id: Optional[int] = None) -> None:
        tid = thread_id or threading.current_thread().ident
        with self._lock:
            self._thread_last_activity[tid] = time.time()

    def add_deadlock_callback(self, callback: Callable[[DeadlockInfo], None]) -> None:
        if callback not in self._deadlock_callbacks:
            self._deadlock_callbacks.append(callback)

    def remove_deadlock_callback(self, callback: Callable[[DeadlockInfo], None]) -> None:
        if callback in self._deadlock_callbacks:
            self._deadlock_callbacks.remove(callback)

    def _monitor_loop(self) -> None:
        while not self._stop_flag.is_set():
            try:
                self._check_for_deadlocks()
            except Exception as e:
                self.logger.debug(f"死锁检测异常: {e}")

            self._stop_flag.wait(self.check_interval)

    def _check_for_deadlocks(self) -> None:
        current_time = time.time()

        with self._lock:
            deadlocked_threads = []

            for thread_id, last_activity in self._thread_last_activity.items():
                wait_time = current_time - last_activity

                if wait_time > self.threshold_seconds:
                    try:
                        thread = threading.Thread(target=None)
                        thread_name = thread.name if hasattr(thread, 'name') else f"Thread-{thread_id}"
                    except:
                        thread_name = f"Thread-{thread_id}"

                    deadlock_info = DeadlockInfo(
                        thread_id=thread_id,
                        thread_name=thread_name,
                        detected_at=datetime.now(),
                        wait_time=wait_time
                    )
                    deadlocked_threads.append(deadlock_info)

        for deadlock_info in deadlocked_threads:
            self.logger.warning(
                f"检测到可能死锁: {deadlock_info.thread_name} "
                f"(等待时间: {deadlock_info.wait_time:.1f}秒)"
            )

            for callback in self._deadlock_callbacks:
                try:
                    callback(deadlock_info)
                except Exception as e:
                    self.logger.debug(f"死锁回调异常: {e}")

    def force_thread_release(self, thread_id: int) -> bool:
        with self._lock:
            if thread_id in self._thread_last_activity:
                del self._thread_last_activity[thread_id]
                self.logger.info(f"已释放线程: {thread_id}")
                return True
        return False

    def get_thread_status(self) -> Dict[int, float]:
        with self._lock:
            return self._thread_last_activity.copy()


class BlackWhiteList:
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger("BlackWhiteList")

        self._blacklist_ips: Set[str] = set()
        self._blacklist_ports: Set[int] = set()
        self._whitelist_ips: Set[str] = set()
        self._whitelist_ports: Set[int] = set()

        self._offline_hosts: Set[str] = set()
        self._consecutive_failures: Dict[str, int] = defaultdict(int)
        self._offline_threshold = 3

        self._lock = threading.Lock()

    def is_blacklisted(self, ip: str, port: Optional[int] = None) -> bool:
        with self._lock:
            if ip in self._blacklist_ips:
                return True
            if port and port in self._blacklist_ports:
                return True
            return False

    def is_whitelisted(self, ip: str, port: Optional[int] = None) -> bool:
        with self._lock:
            if ip in self._whitelist_ips:
                return True
            if port and port in self._whitelist_ports:
                return True
            return False

    def add_to_blacklist(self, ip: Optional[str] = None,
                          port: Optional[int] = None) -> None:
        with self._lock:
            if ip:
                self._blacklist_ips.add(ip)
                self.logger.info(f"IP已加入黑名单: {ip}")
            if port is not None:
                self._blacklist_ports.add(port)
                self.logger.info(f"端口已加入黑名单: {port}")

    def add_to_whitelist(self, ip: Optional[str] = None,
                         port: Optional[int] = None) -> None:
        with self._lock:
            if ip:
                self._whitelist_ips.add(ip)
                self.logger.info(f"IP已加入白名单: {ip}")
            if port is not None:
                self._whitelist_ports.add(port)
                self.logger.info(f"端口已加入白名单: {port}")

    def remove_from_blacklist(self, ip: Optional[str] = None,
                              port: Optional[int] = None) -> None:
        with self._lock:
            if ip:
                self._blacklist_ips.discard(ip)
            if port is not None:
                self._blacklist_ports.discard(port)

    def remove_from_whitelist(self, ip: Optional[str] = None,
                              port: Optional[int] = None) -> None:
        with self._lock:
            if ip:
                self._whitelist_ips.discard(ip)
            if port is not None:
                self._whitelist_ports.discard(port)

    def should_skip(self, ip: str, port: Optional[int] = None) -> bool:
        with self._lock:
            if ip in self._offline_hosts:
                return True
            if self.is_blacklisted(ip, port):
                return True
            if self._whitelist_ips and not self.is_whitelisted(ip, port):
                return True
            return False

    def mark_offline(self, ip: str) -> None:
        with self._lock:
            self._offline_hosts.add(ip)
            self.logger.info(f"主机已标记为离线: {ip}")

    def mark_online(self, ip: str) -> None:
        with self._lock:
            if ip in self._offline_hosts:
                self._offline_hosts.discard(ip)
            self._consecutive_failures[ip] = 0

    def record_failure(self, ip: str) -> None:
        with self._lock:
            self._consecutive_failures[ip] += 1
            if self._consecutive_failures[ip] >= self._offline_threshold:
                self._offline_hosts.add(ip)
                self.logger.warning(f"主机连续失败{self._offline_threshold}次，标记为离线: {ip}")

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._consecutive_failures[ip] = 0
            if ip in self._offline_hosts:
                self._offline_hosts.discard(ip)

    def get_blacklist_ips(self) -> List[str]:
        with self._lock:
            return list(self._blacklist_ips)

    def get_offline_hosts(self) -> List[str]:
        with self._lock:
            return list(self._offline_hosts)

    def clear_offline_hosts(self) -> None:
        with self._lock:
            self._offline_hosts.clear()
            self._consecutive_failures.clear()
        self.logger.info("离线主机列表已清空")


class FaultToleranceManager:
    def __init__(self,
                 timeout_manager: Optional[TimeoutManager] = None,
                 retry_manager: Optional[RetryManager] = None,
                 deadlock_detector: Optional[DeadlockDetector] = None,
                 blacklist: Optional[BlackWhiteList] = None,
                 logger: Logger = None):
        self.timeout_manager = timeout_manager or TimeoutManager()
        self.retry_manager = retry_manager or RetryManager()
        self.deadlock_detector = deadlock_detector or DeadlockDetector()
        self.blacklist = blacklist or BlackWhiteList()
        self.logger = logger or Logger("FaultTolerance")

        self._scan_callbacks: List[Callable] = []
        self._is_scanning = False

    def start_monitoring(self) -> None:
        self.deadlock_detector.start()
        self._is_scanning = True

    def stop_monitoring(self) -> None:
        self.deadlock_detector.stop()
        self._is_scanning = False

    def add_scan_callback(self, callback: Callable) -> None:
        if callback not in self._scan_callbacks:
            self._scan_callbacks.append(callback)

    def should_skip_scan(self, ip: str, port: int) -> bool:
        return self.blacklist.should_skip(ip, port)

    def execute_with_retry(self, scan_func: Callable,
                           ip: str, port: int) -> RetryResult:
        attempts = 0
        last_result: Optional[PortResult] = None

        while attempts <= self.retry_manager.max_retries:
            if not self.should_skip_scan(ip, port):
                break

            attempts += 1
            self.retry_manager.record_attempt(ip, port)

            try:
                result = scan_func(ip, port)
                last_result = result

                if result.status == PortStatus.OPEN:
                    self.blacklist.record_success(ip)
                    return RetryResult(
                        success=True,
                        attempts=attempts,
                        final_status=result.status
                    )

                if attempts <= self.retry_manager.max_retries:
                    timeout_type = self.retry_manager.classify_timeout(result)
                    delay = self.retry_manager.get_retry_delay(timeout_type)
                    time.sleep(delay)

            except Exception as e:
                self.logger.debug(f"扫描异常 {ip}:{port}: {e}")
                self.blacklist.record_failure(ip)

                if attempts > self.retry_manager.max_retries:
                    return RetryResult(
                        success=False,
                        attempts=attempts,
                        final_status=PortStatus.UNKNOWN,
                        error_message=str(e)
                    )

        if last_result:
            return RetryResult(
                success=False,
                attempts=attempts,
                final_status=last_result.status
            )

        return RetryResult(
            success=False,
            attempts=attempts,
            final_status=PortStatus.UNKNOWN
        )

    def handle_deadlock(self, deadlock_info: DeadlockInfo) -> None:
        self.logger.warning(
            f"处理死锁: {deadlock_info.thread_name}, "
            f"等待时间: {deadlock_info.wait_time:.1f}秒"
        )

        self.deadlock_detector.force_thread_release(deadlock_info.thread_id)

    def reset_all(self) -> None:
        self.timeout_manager.clear_all()
        self.retry_manager.clear_all()
        self.blacklist.clear_offline_hosts()
        self.logger.info("容错管理器已重置")
