import psutil
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, List
from datetime import datetime

from core.logger import Logger


@dataclass
class BandwidthSample:
    timestamp: datetime
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    usage_percent: float = 0.0


@dataclass
class BandwidthStats:
    current_usage: float = 0.0
    avg_usage: float = 0.0
    peak_usage: float = 0.0
    total_sent: int = 0
    total_recv: int = 0
    samples_count: int = 0


class BandwidthMonitor:
    def __init__(self,
                 threshold_percent: float = 30.0,
                 check_interval: float = 1.0,
                 window_size: int = 10,
                 logger: Logger = None):
        self.threshold_percent = threshold_percent
        self.check_interval = check_interval
        self.window_size = window_size
        self.logger = logger or Logger("BandwidthMonitor")

        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._is_running = False

        self._samples: List[BandwidthSample] = []
        self._lock = threading.Lock()

        self._last_bytes_sent = 0
        self._last_bytes_recv = 0
        self._last_check_time: Optional[datetime] = None

        self._callbacks: List[Callable[[float], None]] = []

    def start(self) -> None:
        if self._is_running:
            self.logger.warning("带宽监控已在运行")
            return

        self._stop_flag.clear()
        self._is_running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self.logger.info(f"带宽监控已启动 (阈值: {self.threshold_percent}%)")

    def stop(self) -> None:
        if not self._is_running:
            return

        self._stop_flag.set()
        self._is_running = False

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

        self.logger.info("带宽监控已停止")

    def is_running(self) -> bool:
        return self._is_running

    def _monitor_loop(self) -> None:
        net_io_start = psutil.net_io_counters()
        self._last_bytes_sent = net_io_start.bytes_sent
        self._last_bytes_recv = net_io_start.bytes_recv
        self._last_check_time = datetime.now()

        while not self._stop_flag.is_set():
            try:
                self._collect_sample()
                self._notify_callbacks()

                self._stop_flag.wait(self.check_interval)
            except Exception as e:
                self.logger.debug(f"带宽监控异常: {e}")

    def _collect_sample(self) -> None:
        try:
            net_io = psutil.net_io_counters()
            current_time = datetime.now()

            time_delta = (current_time - self._last_check_time).total_seconds()
            if time_delta <= 0:
                time_delta = 0.001

            bytes_sent_delta = net_io.bytes_sent - self._last_bytes_sent
            bytes_recv_delta = net_io.bytes_recv - self._last_bytes_recv

            bandwidth_usage = self._calculate_bandwidth_usage(
                bytes_sent_delta + bytes_recv_delta,
                time_delta
            )

            sample = BandwidthSample(
                timestamp=current_time,
                bytes_sent=bytes_sent_delta,
                bytes_recv=bytes_recv_delta,
                packets_sent=net_io.packets_sent,
                packets_recv=net_io.packets_recv,
                usage_percent=bandwidth_usage
            )

            with self._lock:
                self._samples.append(sample)
                if len(self._samples) > self.window_size:
                    self._samples.pop(0)

                self._last_bytes_sent = net_io.bytes_sent
                self._last_bytes_recv = net_io.bytes_recv
                self._last_check_time = current_time

        except Exception as e:
            self.logger.debug(f"采集带宽样本异常: {e}")

    def _calculate_bandwidth_usage(self, bytes_delta: int, time_delta: float) -> float:
        try:
            max_bandwidth = 100 * 1024 * 1024
            bytes_per_second = bytes_delta / time_delta if time_delta > 0 else 0
            usage = (bytes_per_second / max_bandwidth) * 100
            return min(usage, 100.0)
        except:
            return 0.0

    def _notify_callbacks(self) -> None:
        current_usage = self.get_current_usage()

        if current_usage > self.threshold_percent:
            for callback in self._callbacks:
                try:
                    callback(current_usage)
                except Exception as e:
                    self.logger.debug(f"带宽回调异常: {e}")

    def add_callback(self, callback: Callable[[float], None]) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[float], None]) -> None:
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def get_current_usage(self) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            return self._samples[-1].usage_percent

    def get_stats(self) -> BandwidthStats:
        with self._lock:
            if not self._samples:
                return BandwidthStats()

            latest_sample = self._samples[-1]
            total_sent = sum(s.bytes_sent for s in self._samples)
            total_recv = sum(s.bytes_recv for s in self._samples)

            usages = [s.usage_percent for s in self._samples]
            avg_usage = sum(usages) / len(usages) if usages else 0.0
            peak_usage = max(usages) if usages else 0.0

            return BandwidthStats(
                current_usage=latest_sample.usage_percent,
                avg_usage=avg_usage,
                peak_usage=peak_usage,
                total_sent=total_sent,
                total_recv=total_recv,
                samples_count=len(self._samples)
            )

    def get_samples(self) -> List[BandwidthSample]:
        with self._lock:
            return self._samples.copy()

    def is_threshold_exceeded(self) -> bool:
        return self.get_current_usage() > self.threshold_percent

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()
            self._last_bytes_sent = 0
            self._last_bytes_recv = 0
            self._last_check_time = None
        self.logger.info("带宽监控数据已重置")


class AdaptiveBandwidthController:
    def __init__(self,
                 monitor: BandwidthMonitor,
                 initial_workers: int = 50,
                 min_workers: int = 5,
                 max_workers: int = 200,
                 logger: Logger = None):
        self.monitor = monitor
        self.initial_workers = initial_workers
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.logger = logger or Logger("BandwidthController")

        self._current_workers = initial_workers
        self._adjustment_factor = 0.5
        self._recovery_factor = 1.2

        self._lock = threading.Lock()

        self.monitor.add_callback(self._on_bandwidth_exceeded)

    def _on_bandwidth_exceeded(self, usage: float) -> None:
        with self._lock:
            if usage > self.monitor.threshold_percent:
                new_workers = int(self._current_workers * self._adjustment_factor)
                new_workers = max(new_workers, self.min_workers)

                if new_workers < self._current_workers:
                    self.logger.warning(
                        f"带宽过高({usage:.1f}%), 降低线程数: "
                        f"{self._current_workers} -> {new_workers}"
                    )
                    self._current_workers = new_workers

    def adjust_workers(self, bandwidth_usage: float) -> int:
        with self._lock:
            if bandwidth_usage > self.monitor.threshold_percent:
                new_workers = int(self._current_workers * self._adjustment_factor)
                new_workers = max(new_workers, self.min_workers)
            else:
                if self._current_workers < self.max_workers:
                    new_workers = min(
                        int(self._current_workers * self._recovery_factor),
                        self.max_workers
                    )
                else:
                    new_workers = self._current_workers

            self._current_workers = new_workers
            return self._current_workers

    def get_current_workers(self) -> int:
        with self._lock:
            return self._current_workers

    def set_workers(self, workers: int) -> None:
        with self._lock:
            self._current_workers = max(self.min_workers, min(workers, self.max_workers))

    def reset(self) -> None:
        with self._lock:
            self._current_workers = self.initial_workers


def get_system_bandwidth() -> dict:
    try:
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
        }
    except Exception:
        return {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
        }


def format_bandwidth(bytes_per_second: float) -> str:
    units = ['B/s', 'KB/s', 'MB/s', 'GB/s']
    unit_index = 0

    value = bytes_per_second
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1

    return f"{value:.2f} {units[unit_index]}"
