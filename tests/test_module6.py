import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scheduler.task_scheduler import (
    TaskScheduler, AdaptiveScheduler, BatchScheduler,
    SchedulerConfig, create_scheduler
)
from core.port_scanner import PortStatus


def test_scheduler_config():
    print("\n" + "=" * 60)
    print("测试6.1: 调度器配置")
    print("=" * 60)

    try:
        config = SchedulerConfig(
            max_workers=100,
            min_workers=10,
            timeout=5.0,
            retry_count=3,
            batch_size=50
        )

        print(f"  max_workers: {config.max_workers}")
        print(f"  min_workers: {config.min_workers}")
        print(f"  timeout: {config.timeout}")
        print(f"  retry_count: {config.retry_count}")
        print(f"  batch_size: {config.batch_size}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_basic_scheduler():
    print("\n" + "=" * 60)
    print("测试6.2: 基础调度器")
    print("=" * 60)

    try:
        config = SchedulerConfig(
            max_workers=10,
            min_workers=5,
            timeout=2.0,
            retry_count=1
        )
        scheduler = TaskScheduler(config)

        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 3306]

        print(f"  扫描: {targets} 端口: {ports}")
        start_time = time.time()
        results = scheduler.scan(targets, ports)
        elapsed = time.time() - start_time

        print(f"  扫描完成: {len(results)}个结果, 耗时:{elapsed:.2f}秒")

        open_count = sum(1 for r in results if r.status == PortStatus.OPEN)
        print(f"  开放端口: {open_count}")

        for r in results:
            print(f"    {r.ip}:{r.port} -> {r.status.value} ({r.response_time_ms:.2f}ms)")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_adaptive_scheduler():
    print("\n" + "=" * 60)
    print("测试6.3: 自适应调度器")
    print("=" * 60)

    try:
        config = SchedulerConfig(
            max_workers=20,
            min_workers=5,
            timeout=2.0
        )
        scheduler = AdaptiveScheduler(config)

        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 3306, 5432]

        print(f"  当前线程数: {scheduler.get_current_workers()}")

        def bandwidth_callback(usage):
            print(f"  带宽回调: {usage:.1f}%")

        scheduler.set_bandwidth_callback(bandwidth_callback)

        results = scheduler.scan(targets, ports)

        print(f"  扫描完成: {len(results)}个结果")
        print(f"  最终线程数: {scheduler.get_current_workers()}")

        scheduler.adjust_workers(50.0)
        print(f"  调整后线程数(高带宽): {scheduler.get_current_workers()}")

        scheduler.adjust_workers(10.0)
        print(f"  调整后线程数(低带宽): {scheduler.get_current_workers()}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_batch_scheduler():
    print("\n" + "=" * 60)
    print("测试6.4: 分批调度器")
    print("=" * 60)

    try:
        config = SchedulerConfig(
            max_workers=10,
            timeout=2.0,
            batch_size=3
        )
        scheduler = BatchScheduler(config)

        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 3306, 5432, 6379]

        batch_count = 0

        def batch_callback(batch_num, batch_results):
            nonlocal batch_count
            batch_count += 1
            print(f"  批次{batch_count}: {len(batch_results)}个结果")
            for r in batch_results:
                print(f"    {r.ip}:{r.port} -> {r.status.value}")

        print(f"  总端口: {len(ports)}, 批大小: {config.batch_size}")
        all_batches = scheduler.scan_with_batches(targets, ports, batch_callback)

        print(f"  分批扫描完成: {len(all_batches)}批")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_create_scheduler():
    print("\n" + "=" * 60)
    print("测试6.5: 工厂函数")
    print("=" * 60)

    try:
        config = SchedulerConfig(max_workers=10)

        default_scheduler = create_scheduler("default", config)
        print(f"  默认调度器: {type(default_scheduler).__name__}")

        adaptive_scheduler = create_scheduler("adaptive", config)
        print(f"  自适应调度器: {type(adaptive_scheduler).__name__}")

        batch_scheduler = create_scheduler("batch", config)
        print(f"  分批调度器: {type(batch_scheduler).__name__}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_scheduler_stats():
    print("\n" + "=" * 60)
    print("测试6.6: 调度器统计")
    print("=" * 60)

    try:
        config = SchedulerConfig(max_workers=10, timeout=2.0)
        scheduler = TaskScheduler(config)

        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 3306, 8080]

        results = scheduler.scan(targets, ports)

        stats = scheduler.get_stats()
        print(f"  统计信息: {stats}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_progress_callback():
    print("\n" + "=" * 60)
    print("测试6.7: 进度回调")
    print("=" * 60)

    try:
        config = SchedulerConfig(max_workers=10, timeout=2.0)
        scheduler = TaskScheduler(config)

        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 3306, 5432, 6379, 27017, 8080]

        progress_updates = []

        def progress_callback(current, total):
            percent = 100 * current / total if total > 0 else 0
            progress_updates.append((current, total, percent))
            print(f"  进度: {current}/{total} ({percent:.1f}%)")

        results = scheduler.scan(targets, ports, progress_callback)

        print(f"  进度更新次数: {len(progress_updates)}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multi_target():
    print("\n" + "=" * 60)
    print("测试6.8: 多目标扫描")
    print("=" * 60)

    try:
        config = SchedulerConfig(max_workers=10, timeout=2.0)
        scheduler = TaskScheduler(config)

        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 3306]

        start_time = time.time()
        results = scheduler.scan(targets, ports)
        elapsed = time.time() - start_time

        print(f"  扫描{len(targets)}个IP, {len(ports)}个端口")
        print(f"  总耗时: {elapsed:.2f}秒")

        unique_ips = set(r.ip for r in results)
        print(f"  唯一IP数: {len(unique_ips)}")

        open_by_ip = {}
        for r in results:
            if r.status == PortStatus.OPEN:
                if r.ip not in open_by_ip:
                    open_by_ip[r.ip] = []
                open_by_ip[r.ip].append(r.port)

        for ip, ports in open_by_ip.items():
            print(f"  {ip} 开放端口: {ports}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_stop_scheduler():
    print("\n" + "=" * 60)
    print("测试6.9: 停止调度器")
    print("=" * 60)

    try:
        config = SchedulerConfig(max_workers=5, timeout=2.0)
        scheduler = TaskScheduler(config)

        targets = ["127.0.0.1"]
        ports = list(range(80, 100))

        def stop_after_delay():
            time.sleep(0.5)
            scheduler.stop()

        import threading
        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        results = scheduler.scan(targets, ports)
        stop_thread.join()

        print(f"  扫描被停止")
        print(f"  已获取结果: {len(results)}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块6 测试套件")
    print("测试内容: 任务调度模块（并发控制）")
    print("=" * 60)

    results = []

    results.append(("调度器配置", test_scheduler_config()))
    results.append(("基础调度器", test_basic_scheduler()))
    results.append(("自适应调度器", test_adaptive_scheduler()))
    results.append(("分批调度器", test_batch_scheduler()))
    results.append(("工厂函数", test_create_scheduler()))
    results.append(("调度器统计", test_scheduler_stats()))
    results.append(("进度回调", test_progress_callback()))
    results.append(("多目标扫描", test_multi_target()))
    results.append(("停止调度器", test_stop_scheduler()))

    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)

    passed = 0
    failed = 0

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {name}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n总计: {passed} 通过, {failed} 失败")

    if failed == 0:
        print("\n模块6 测试全部通过!")
    else:
        print("\n模块6 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
