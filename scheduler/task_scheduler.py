import concurrent.futures
import threading
import time
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable, Dict, Any
from queue import Queue, Empty

from core.port_scanner import PortScanner, PortResult, PortStatus
from core.async_port_scanner import AsyncPortScanner
from core.service_detector import ServiceDetector
from core.logger import Logger
from core.exceptions import ThreadDeadlockError
from output.display import ProgressTracker


@dataclass
class SchedulerConfig:
    max_workers: int = 50
    min_workers: int = 5
    timeout: float = 3.0
    retry_count: int = 2
    batch_size: int = 100
    deadlock_threshold: int = 30
    deadlock_check_interval: float = 5.0


class TaskScheduler:
    def __init__(self, config: Optional[SchedulerConfig] = None, logger: Logger = None):
        self.config = config or SchedulerConfig()
        self.logger = logger or Logger("TaskScheduler")
        self.scanner = PortScanner(
            timeout=self.config.timeout,
            retry_count=self.config.retry_count
        )
        self.async_scanner = AsyncPortScanner(timeout=self.config.timeout)
        self.service_detector = ServiceDetector()
        self._lock = threading.Lock()
        self._results: List[PortResult] = []
        self._is_running = False
        self._stop_flag = threading.Event()
        self._was_stopped = False
        self._thread_health: Dict[int, float] = {}
        self._thread_lock_status: Dict[int, bool] = {}

    def scan(self, targets: List[str], ports: List[int],
             progress_callback: Optional[Callable] = None,
             thread_count: Optional[int] = None,
             use_async: bool = False,
             result_callback: Optional[Callable] = None,
             scan_protocol: str = "tcp") -> List[PortResult]:
        if use_async:
            return self._scan_async(targets, ports, progress_callback)
        else:
            return self._scan_sync(targets, ports, progress_callback, thread_count, result_callback, scan_protocol)

    def _scan_sync(self, targets: List[str], ports: List[int],
                   progress_callback: Optional[Callable] = None,
                   thread_count: Optional[int] = None,
                   result_callback: Optional[Callable] = None,
                   scan_protocol: str = "tcp") -> List[PortResult]:
        workers = thread_count or self.config.max_workers
        workers = min(workers, self.config.max_workers)
        workers = max(workers, self.config.min_workers)

        self._results.clear()
        self._is_running = True
        self._was_stopped = False
        self._stop_flag.clear()

        tasks = self._create_tasks(targets, ports)
        total_tasks = len(tasks)

        self.logger.info(f"开始扫描({scan_protocol}同步): {len(targets)}个IP, {len(ports)}个端口, {total_tasks}个任务, {workers}个工作线程")

        start_time = time.time()

        if progress_callback:
            progress_callback(0, total_tasks)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_task = {
                executor.submit(self._scan_task, task, scan_protocol): task
                for task in tasks
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_task):
                if self._stop_flag.is_set():
                    self._was_stopped = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                task = future_to_task[future]
                try:
                    result = future.result()
                    with self._lock:
                        if result:
                            self._results.append(result)
                        completed += 1

                    if result_callback and result:
                        result_callback(result)

                    if progress_callback:
                        # 计算当前开放端口数量
                        open_count = sum(1 for r in self._results if r.status == PortStatus.OPEN)
                        progress_callback(completed, total_tasks, open_count)

                except Exception as e:
                    self.logger.debug(f"任务执行异常: {task}, 错误: {e}")
                    with self._lock:
                        completed += 1
                    if progress_callback:
                        progress_callback(completed, total_tasks)

        self._is_running = False
        elapsed = time.time() - start_time

        self.logger.info(f"扫描完成({scan_protocol}同步): {len(self._results)}个结果, 耗时:{elapsed:.2f}秒")

        return self._results

    def _scan_async(self, targets: List[str], ports: List[int],
                    progress_callback: Optional[Callable] = None) -> List[PortResult]:
        self._results.clear()
        self._is_running = True
        self._stop_flag.clear()

        total_tasks = len(targets) * len(ports)

        self.logger.info(f"开始扫描(异步): {len(targets)}个IP, {len(ports)}个端口, {total_tasks}个任务")

        start_time = time.time()

        if progress_callback:
            progress_callback(0, total_tasks)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            all_results = []
            for target in targets:
                results = loop.run_until_complete(
                    self.async_scanner.scan_batch(
                        target, ports,
                        lambda c, t: progress_callback(c + len(all_results) * len(ports), total_tasks) if progress_callback else None
                    )
                )
                all_results.extend(results)

            for result in all_results:
                result.service = self.service_detector.detect(result.port)

            self._results = all_results

        finally:
            loop.close()

        self._is_running = False
        elapsed = time.time() - start_time

        self.logger.info(f"扫描完成(异步): {len(self._results)}个结果, 耗时:{elapsed:.2f}秒")

        return self._results

    def _create_tasks(self, targets: List[str], ports: List[int]) -> List[tuple]:
        tasks = []
        for target in targets:
            for port in ports:
                tasks.append((target, port))
        return tasks

    def _scan_task(self, task: tuple, scan_protocol: str = "tcp") -> Optional[PortResult]:
        ip, port = task

        if self._stop_flag.is_set():
            return None

        thread_id = threading.current_thread().ident
        self._update_thread_health(thread_id)

        try:
            if scan_protocol == "udp":
                result = self.scanner.scan_udp(ip, port)
            else:
                result = self.scanner.scan(ip, port)

            result.service = self.service_detector.detect(port)

            self._thread_lock_status[thread_id] = False

            return result

        except Exception as e:
            self.logger.debug(f"扫描异常: {ip}:{port}, 错误: {e}")
            return PortResult(
                ip=ip,
                port=port,
                status=PortStatus.UNKNOWN,
                error_message=str(e),
                protocol=scan_protocol,
                scan_type="udp" if scan_protocol == "udp" else "tcp_connect"
            )

    def _update_thread_health(self, thread_id: int) -> None:
        with self._lock:
            self._thread_health[thread_id] = time.time()

    def stop(self) -> None:
        self.logger.info("停止扫描")
        self._stop_flag.set()
        self._was_stopped = True
        self._is_running = False

    def is_running(self) -> bool:
        return self._is_running

    def was_stopped(self) -> bool:
        return self._was_stopped

    def get_results(self) -> List[PortResult]:
        with self._lock:
            return self._results.copy()

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'total_results': len(self._results),
                'open_count': sum(1 for r in self._results if r.status == PortStatus.OPEN),
                'closed_count': sum(1 for r in self._results if r.status == PortStatus.CLOSED),
                'filtered_count': sum(1 for r in self._results if r.status == PortStatus.FILTERED),
                'thread_count': len(self._thread_health),
            }


class AdaptiveScheduler(TaskScheduler):
    def __init__(self, config: Optional[SchedulerConfig] = None, logger: Logger = None):
        super().__init__(config, logger)
        self._current_workers = config.max_workers if config else 50
        self._bandwidth_threshold = 30.0
        self._bandwidth_check_interval = 1.0
        self._monitor_thread: Optional[threading.Thread] = None
        self._bandwidth_callback: Optional[Callable[[float], None]] = None

    def set_bandwidth_callback(self, callback: Callable[[float], None]) -> None:
        self._bandwidth_callback = callback

    def scan(self, targets: List[str], ports: List[int],
             progress_callback: Optional[Callable] = None,
             thread_count: Optional[int] = None) -> List[PortResult]:
        workers = thread_count or self._current_workers

        self.logger.info(f"自适应调度扫描: {workers}个工作线程")

        return super().scan(targets, ports, progress_callback, workers)

    def adjust_workers(self, bandwidth_usage: float) -> int:
        if bandwidth_usage > self._bandwidth_threshold:
            new_workers = int(self._current_workers * 0.5)
            new_workers = max(new_workers, self.config.min_workers)

            if new_workers != self._current_workers:
                self.logger.warning(
                    f"带宽使用率过高({bandwidth_usage:.1f}%), "
                    f"降低线程数: {self._current_workers} -> {new_workers}"
                )
                self._current_workers = new_workers

                if self._bandwidth_callback:
                    self._bandwidth_callback(bandwidth_usage)
        else:
            if self._current_workers < self.config.max_workers:
                new_workers = min(
                    int(self._current_workers * 1.2),
                    self.config.max_workers
                )

                if new_workers != self._current_workers:
                    self.logger.info(
                        f"带宽使用率正常({bandwidth_usage:.1f}%), "
                        f"提高线程数: {self._current_workers} -> {new_workers}"
                    )
                    self._current_workers = new_workers

                    if self._bandwidth_callback:
                        self._bandwidth_callback(bandwidth_usage)

        return self._current_workers

    def get_current_workers(self) -> int:
        return self._current_workers


class BatchScheduler(TaskScheduler):
    def __init__(self, config: Optional[SchedulerConfig] = None, logger: Logger = None):
        super().__init__(config, logger)
        self._batch_results: List[List[PortResult]] = []
        self._current_batch = 0

    def scan_with_batches(self, targets: List[str], ports: List[int],
                          batch_callback: Optional[Callable[[int, List[PortResult]], None]] = None,
                          thread_count: Optional[int] = None) -> List[List[PortResult]]:
        workers = thread_count or self.config.max_workers
        batch_size = self.config.batch_size

        all_tasks = self._create_tasks(targets, ports)
        total_tasks = len(all_tasks)

        self.logger.info(f"分批扫描: {total_tasks}个任务, 每批{batch_size}个")

        self._batch_results.clear()
        self._is_running = True
        self._stop_flag.clear()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            batch_tasks = []
            batch_results = []

            for i, task in enumerate(all_tasks):
                if self._stop_flag.is_set():
                    break

                future = executor.submit(self._scan_task, task)
                batch_tasks.append((future, task))

                if len(batch_tasks) >= batch_size or i == len(all_tasks) - 1:
                    for future, task in batch_tasks:
                        try:
                            result = future.result()
                            if result:
                                batch_results.append(result)
                        except Exception:
                            pass

                    self._batch_results.append(batch_results.copy())

                    if batch_callback:
                        self._current_batch += 1
                        batch_callback(self._current_batch, batch_results)

                    batch_tasks.clear()
                    batch_results.clear()

        self._is_running = False

        self.logger.info(f"分批扫描完成: {len(self._batch_results)}批")

        return self._batch_results

    def get_batch_results(self) -> List[List[PortResult]]:
        return self._batch_results.copy()


def create_scheduler(scheduler_type: str = "default",
                     config: Optional[SchedulerConfig] = None,
                     logger: Logger = None) -> TaskScheduler:
    if scheduler_type == "adaptive":
        return AdaptiveScheduler(config, logger)
    elif scheduler_type == "batch":
        return BatchScheduler(config, logger)
    else:
        return TaskScheduler(config, logger)
