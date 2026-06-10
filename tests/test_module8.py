import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.fault_tolerance import (
    TimeoutManager, RetryManager, DeadlockDetector, BlackWhiteList,
    FaultToleranceManager, TimeoutType, DeadlockInfo
)
from core.port_scanner import PortResult, PortStatus


def test_timeout_manager():
    print("\n" + "=" * 60)
    print("测试8.1: 超时管理器")
    print("=" * 60)

    try:
        manager = TimeoutManager(default_timeout=3.0, max_timeout=30.0)

        timeout = manager.get_timeout("192.168.1.1", 80)
        print(f"  默认超时: {timeout}s")

        manager.set_timeout("192.168.1.1", 80, 5.0)
        timeout = manager.get_timeout("192.168.1.1", 80)
        print(f"  设置后超时: {timeout}s")

        manager.set_timeout("192.168.1.1", 80, 100.0)
        timeout = manager.get_timeout("192.168.1.1", 80)
        print(f"  超限后超时(应被限制在max): {timeout}s")

        manager.remove_timeout("192.168.1.1", 80)
        timeout = manager.get_timeout("192.168.1.1", 80)
        print(f"  移除后超时: {timeout}s")

        manager.clear_all()
        print("  全部清除完成")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_retry_manager():
    print("\n" + "=" * 60)
    print("测试8.2: 重试管理器")
    print("=" * 60)

    try:
        manager = RetryManager(max_retries=3, network_retry_delay=0.1)

        should_retry = manager.should_retry("192.168.1.1", 80)
        print(f"  初始应重试: {should_retry}")

        manager.record_attempt("192.168.1.1", 80)
        manager.record_attempt("192.168.1.1", 80)

        attempts = manager.get_attempt_count("192.168.1.1", 80)
        print(f"  当前尝试次数: {attempts}")

        should_retry = manager.should_retry("192.168.1.1", 80)
        print(f"  还可重试: {should_retry}")

        delay = manager.get_retry_delay(TimeoutType.NETWORK)
        print(f"  网络超时延迟: {delay}s")

        manager.reset_attempts("192.168.1.1", 80)
        attempts = manager.get_attempt_count("192.168.1.1", 80)
        print(f"  重置后次数: {attempts}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_retry_classification():
    print("\n" + "=" * 60)
    print("测试8.3: 超时类型分类")
    print("=" * 60)

    try:
        manager = RetryManager()

        result1 = PortResult(
            ip="192.168.1.1",
            port=80,
            status=PortStatus.UNKNOWN,
            error_message="Connection timeout"
        )
        type1 = manager.classify_timeout(result1)
        print(f"  连接超时 -> {type1.value}")

        result2 = PortResult(
            ip="192.168.1.1",
            port=80,
            status=PortStatus.UNKNOWN,
            error_message="Service unavailable",
            response_time_ms=3000
        )
        type2 = manager.classify_timeout(result2)
        print(f"  服务异常 -> {type2.value}")

        result3 = PortResult(
            ip="192.168.1.1",
            port=80,
            status=PortStatus.CLOSED,
            response_time_ms=100
        )
        type3 = manager.classify_timeout(result3)
        print(f"  正常响应 -> {type3.value}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_deadlock_detector():
    print("\n" + "=" * 60)
    print("测试8.4: 死锁检测器")
    print("=" * 60)

    try:
        detector = DeadlockDetector(threshold_seconds=2.0, check_interval=0.5)

        detector.register_thread()
        thread_id = threading.current_thread().ident
        print(f"  注册当前线程: {thread_id}")

        time.sleep(0.5)
        detector.update_thread_activity()
        print("  更新线程活动")

        deadlocks = []

        def deadlock_callback(info: DeadlockInfo):
            deadlocks.append(info)
            print(f"  死锁回调: {info.thread_name}, 等待: {info.wait_time:.1f}秒")

        detector.add_deadlock_callback(deadlock_callback)

        detector.start()
        time.sleep(3)

        detector.stop()

        print(f"  检测到的死锁数: {len(deadlocks)}")

        detector.remove_deadlock_callback(deadlock_callback)

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_deadlock_force_release():
    print("\n" + "=" * 60)
    print("测试8.5: 强制释放线程")
    print("=" * 60)

    try:
        detector = DeadlockDetector(threshold_seconds=2.0)

        detector.register_thread()
        thread_id = threading.current_thread().ident

        status = detector.get_thread_status()
        print(f"  当前线程数: {len(status)}")

        released = detector.force_thread_release(thread_id)
        print(f"  释放结果: {released}")

        status = detector.get_thread_status()
        print(f"  释放后线程数: {len(status)}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_blackwhitelist():
    print("\n" + "=" * 60)
    print("测试8.6: 黑名单管理")
    print("=" * 60)

    try:
        blacklist = BlackWhiteList()

        is_blacklisted = blacklist.is_blacklisted("192.168.1.100")
        print(f"  初始黑名单: {is_blacklisted}")

        blacklist.add_to_blacklist(ip="192.168.1.100")
        blacklist.add_to_blacklist(port=8080)

        is_blacklisted = blacklist.is_blacklisted("192.168.1.100")
        print(f"  添加IP后黑名单: {is_blacklisted}")

        is_blacklisted = blacklist.is_blacklisted("192.168.1.1", 8080)
        print(f"  添加端口后黑名单: {is_blacklisted}")

        blacklist.remove_from_blacklist(ip="192.168.1.100")
        is_blacklisted = blacklist.is_blacklisted("192.168.1.100")
        print(f"  移除后黑名单: {is_blacklisted}")

        ips = blacklist.get_blacklist_ips()
        print(f"  黑名单IP列表: {ips}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_offline_detection():
    print("\n" + "=" * 60)
    print("测试8.7: 离线主机检测")
    print("=" * 60)

    try:
        blacklist = BlackWhiteList()

        should_skip = blacklist.should_skip("192.168.1.1")
        print(f"  初始跳过: {should_skip}")

        for i in range(3):
            blacklist.record_failure("192.168.1.1")

        offline_hosts = blacklist.get_offline_hosts()
        print(f"  离线主机: {offline_hosts}")

        should_skip = blacklist.should_skip("192.168.1.1")
        print(f"  离线后跳过: {should_skip}")

        blacklist.mark_online("192.168.1.1")
        should_skip = blacklist.should_skip("192.168.1.1")
        print(f"  标记在线后跳过: {should_skip}")

        blacklist.clear_offline_hosts()
        offline_hosts = blacklist.get_offline_hosts()
        print(f"  清空后离线主机: {offline_hosts}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_whitelist():
    print("\n" + "=" * 60)
    print("测试8.8: 白名单管理")
    print("=" * 60)

    try:
        blacklist = BlackWhiteList()

        blacklist.add_to_whitelist(ip="192.168.1.1")
        blacklist.add_to_whitelist(port=80)

        is_whitelisted = blacklist.is_whitelisted("192.168.1.1")
        print(f"  IP白名单: {is_whitelisted}")

        is_whitelisted = blacklist.is_whitelisted("192.168.1.2", 80)
        print(f"  非白名单IP+白名单端口: {is_whitelisted}")

        should_skip = blacklist.should_skip("192.168.1.2", 80)
        print(f"  应跳过(未在白名单): {should_skip}")

        should_skip = blacklist.should_skip("192.168.1.1", 8080)
        print(f"  应跳过(白名单IP+非白名单端口): {should_skip}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_fault_tolerance_manager():
    print("\n" + "=" * 60)
    print("测试8.9: 容错管理器集成")
    print("=" * 60)

    try:
        manager = FaultToleranceManager()

        manager.start_monitoring()
        print("  监控已启动")

        should_skip = manager.should_skip_scan("192.168.1.1", 80)
        print(f"  应跳过: {should_skip}")

        manager.blacklist.add_to_blacklist(ip="192.168.1.1")
        should_skip = manager.should_skip_scan("192.168.1.1", 80)
        print(f"  添加黑名单后应跳过: {should_skip}")

        manager.deadlock_detector.stop()
        print("  监控已停止")

        manager.reset_all()
        print("  管理器已重置")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_scan_callback():
    print("\n" + "=" * 60)
    print("测试8.10: 扫描回调")
    print("=" * 60)

    try:
        manager = FaultToleranceManager()

        callback_count = [0]

        def scan_callback():
            callback_count[0] += 1

        manager.add_scan_callback(scan_callback)
        print(f"  添加回调后计数: {callback_count[0]}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块8 测试套件")
    print("测试内容: 容错机制")
    print("=" * 60)

    results = []

    results.append(("超时管理器", test_timeout_manager()))
    results.append(("重试管理器", test_retry_manager()))
    results.append(("超时类型分类", test_retry_classification()))
    results.append(("死锁检测器", test_deadlock_detector()))
    results.append(("强制释放线程", test_deadlock_force_release()))
    results.append(("黑名单管理", test_blackwhitelist()))
    results.append(("离线主机检测", test_offline_detection()))
    results.append(("白名单管理", test_whitelist()))
    results.append(("容错管理器集成", test_fault_tolerance_manager()))
    results.append(("扫描回调", test_scan_callback()))

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
        print("\n模块8 测试全部通过!")
    else:
        print("\n模块8 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
