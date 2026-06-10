import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.bandwidth_monitor import (
    BandwidthMonitor, AdaptiveBandwidthController, BandwidthStats,
    get_system_bandwidth, format_bandwidth, BandwidthSample
)


def test_bandwidth_monitor_basic():
    print("\n" + "=" * 60)
    print("测试7.1: 带宽监控基础功能")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.5,
            window_size=5
        )

        monitor.start()
        time.sleep(2)

        current_usage = monitor.get_current_usage()
        print(f"  当前带宽使用率: {current_usage:.2f}%")

        stats = monitor.get_stats()
        print(f"  统计信息: 当前={stats.current_usage:.2f}%, 平均={stats.avg_usage:.2f}%, 峰值={stats.peak_usage:.2f}%")
        print(f"  采样次数: {stats.samples_count}")

        monitor.stop()

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_bandwidth_monitor_callback():
    print("\n" + "=" * 60)
    print("测试7.2: 带宽监控回调")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.3
        )

        callback_count = [0]
        last_usage = [0.0]

        def bandwidth_callback(usage):
            callback_count[0] += 1
            last_usage[0] = usage
            print(f"  回调触发 #{callback_count[0]}: {usage:.2f}%")

        monitor.add_callback(bandwidth_callback)
        monitor.start()

        time.sleep(2)

        monitor.remove_callback(bandwidth_callback)
        monitor.stop()

        print(f"  总回调次数: {callback_count[0]}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_bandwidth_monitor_samples():
    print("\n" + "=" * 60)
    print("测试7.3: 带宽采样数据")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.2,
            window_size=10
        )

        monitor.start()
        time.sleep(1)

        samples = monitor.get_samples()
        print(f"  采样数量: {len(samples)}")

        for i, sample in enumerate(samples[:5]):
            print(f"    样本{i+1}: {sample.usage_percent:.2f}%, "
                  f"发送={sample.bytes_sent}, 接收={sample.bytes_recv}")

        monitor.stop()

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_adaptive_controller():
    print("\n" + "=" * 60)
    print("测试7.4: 自适应带宽控制器")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.2
        )

        controller = AdaptiveBandwidthController(
            monitor=monitor,
            initial_workers=50,
            min_workers=5,
            max_workers=100
        )

        print(f"  初始线程数: {controller.get_current_workers()}")

        controller.adjust_workers(50.0)
        print(f"  高带宽调整后: {controller.get_current_workers()}")

        controller.adjust_workers(10.0)
        print(f"  低带宽调整后: {controller.get_current_workers()}")

        controller.set_workers(80)
        print(f"  手动设置后: {controller.get_current_workers()}")

        controller.reset()
        print(f"  重置后: {controller.get_current_workers()}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_adaptive_controller_callback():
    print("\n" + "=" * 60)
    print("测试7.5: 自适应控制器回调触发")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.2
        )

        controller = AdaptiveBandwidthController(
            monitor=monitor,
            initial_workers=50,
            min_workers=5,
            max_workers=100
        )

        monitor.start()

        time.sleep(1)
        print(f"  初始线程数: {controller.get_current_workers()}")

        time.sleep(2)

        stats = monitor.get_stats()
        print(f"  当前带宽: {stats.current_usage:.2f}%")
        print(f"  当前线程数: {controller.get_current_workers()}")

        monitor.stop()

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_system_bandwidth():
    print("\n" + "=" * 60)
    print("测试7.6: 系统带宽信息")
    print("=" * 60)

    try:
        bandwidth = get_system_bandwidth()
        print(f"  发送字节: {bandwidth['bytes_sent']}")
        print(f"  接收字节: {bandwidth['bytes_recv']}")
        print(f"  发送包数: {bandwidth['packets_sent']}")
        print(f"  接收包数: {bandwidth['packets_recv']}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_format_bandwidth():
    print("\n" + "=" * 60)
    print("测试7.7: 带宽格式化")
    print("=" * 60)

    try:
        test_values = [100, 1024, 1024 * 100, 1024 * 1024, 1024 * 1024 * 10]

        for value in test_values:
            formatted = format_bandwidth(value)
            print(f"  {value:>12} -> {formatted}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_monitor_start_stop():
    print("\n" + "=" * 60)
    print("测试7.8: 监控启动/停止")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.2
        )

        print(f"  初始状态: {monitor.is_running()}")

        monitor.start()
        print(f"  启动后: {monitor.is_running()}")

        time.sleep(0.5)

        monitor.stop()
        print(f"  停止后: {monitor.is_running()}")

        monitor.reset()
        print(f"  重置后采样数: {len(monitor.get_samples())}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_concurrent_monitors():
    print("\n" + "=" * 60)
    print("测试7.9: 并发监控")
    print("=" * 60)

    try:
        monitors = []
        for i in range(3):
            monitor = BandwidthMonitor(
                threshold_percent=30.0 + i * 10,
                check_interval=0.3
            )
            monitors.append(monitor)
            monitor.start()

        time.sleep(1)

        for i, monitor in enumerate(monitors):
            usage = monitor.get_current_usage()
            print(f"  监控{i+1}: {usage:.2f}%")

        for monitor in monitors:
            monitor.stop()

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_threshold_check():
    print("\n" + "=" * 60)
    print("测试7.10: 阈值检测")
    print("=" * 60)

    try:
        monitor = BandwidthMonitor(
            threshold_percent=30.0,
            check_interval=0.2
        )

        print(f"  阈值: {monitor.threshold_percent}%")

        monitor.start()
        time.sleep(1)

        is_exceeded = monitor.is_threshold_exceeded()
        current = monitor.get_current_usage()

        print(f"  当前使用率: {current:.2f}%")
        print(f"  超过阈值: {is_exceeded}")

        monitor.stop()

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块7 测试套件")
    print("测试内容: 带宽监控与自适应限速")
    print("=" * 60)

    results = []

    results.append(("带宽监控基础", test_bandwidth_monitor_basic()))
    results.append(("带宽监控回调", test_bandwidth_monitor_callback()))
    results.append(("带宽采样数据", test_bandwidth_monitor_samples()))
    results.append(("自适应控制器", test_adaptive_controller()))
    results.append(("控制器回调触发", test_adaptive_controller_callback()))
    results.append(("系统带宽信息", test_system_bandwidth()))
    results.append(("带宽格式化", test_format_bandwidth()))
    results.append(("监控启动/停止", test_monitor_start_stop()))
    results.append(("并发监控", test_concurrent_monitors()))
    results.append(("阈值检测", test_threshold_check()))

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
        print("\n模块7 测试全部通过!")
    else:
        print("\n模块7 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
