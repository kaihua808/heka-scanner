import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from core.port_scanner import PortResult, PortStatus
from core.service_detector import ServiceDetector
from output.display import (
    ResultDisplay, ScanTask, ScanSummary, ProgressTracker, create_summary
)


def test_scan_task():
    print("\n" + "=" * 60)
    print("测试5.1: 扫描任务数据类")
    print("=" * 60)

    try:
        task = ScanTask(
            target="192.168.1.0/24",
            ports="1-1000"
        )

        print(f"  目标: {task.target}")
        print(f"  端口: {task.ports}")
        print(f"  开始时间: {task.start_time}")
        print(f"  当前持续时间: {task.duration:.2f}秒")

        time.sleep(0.1)
        task.end_time = datetime.now()
        task.total_time = task.duration

        print(f"  结束时间: {task.end_time}")
        print(f"  总耗时: {task.total_time:.2f}秒")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_scan_summary():
    print("\n" + "=" * 60)
    print("测试5.2: 扫描摘要数据类")
    print("=" * 60)

    try:
        summary = ScanSummary()
        summary.total_ips = 10
        summary.total_ports = 1000
        summary.open_count = 5
        summary.closed_count = 990
        summary.filtered_count = 3
        summary.unknown_count = 2
        summary.high_risk_count = 2
        summary.medium_risk_count = 3
        summary.low_risk_count = 0
        summary.scan_duration = 12.5

        print(f"  IP数量: {summary.total_ips}")
        print(f"  端口总数: {summary.total_ports}")
        print(f"  开放: {summary.open_count}, 关闭: {summary.closed_count}, 过滤: {summary.filtered_count}")
        print(f"  高危: {summary.high_risk_count}, 中危: {summary.medium_risk_count}, 低危: {summary.low_risk_count}")
        print(f"  耗时: {summary.scan_duration:.2f}秒")

        summary_dict = summary.to_dict()
        print(f"  to_dict(): {summary_dict}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_create_summary():
    print("\n" + "=" * 60)
    print("测试5.3: 生成扫描摘要")
    print("=" * 60)

    try:
        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=10.5),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP", response_time_ms=8.2),
            PortResult(ip="192.168.1.1", port=443, status=PortStatus.OPEN, service="HTTPS", response_time_ms=9.1),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL", response_time_ms=15.3),
            PortResult(ip="192.168.1.1", port=8080, status=PortStatus.CLOSED, response_time_ms=5.0),
            PortResult(ip="192.168.1.2", port=22, status=PortStatus.FILTERED, response_time_ms=3000.0),
        ]

        summary = create_summary(results, 10.5)

        print(f"  IP数量: {summary.total_ips}")
        print(f"  端口总数: {summary.total_ports}")
        print(f"  开放: {summary.open_count}, 关闭: {summary.closed_count}, 过滤: {summary.filtered_count}")
        print(f"  高危: {summary.high_risk_count}, 中危: {summary.medium_risk_count}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_result_display():
    print("\n" + "=" * 60)
    print("测试5.4: 结果展示")
    print("=" * 60)

    try:
        display = ResultDisplay(show_progress=False)

        task = ScanTask(target="192.168.1.0/24", ports="1-1000")
        display.display_header(task)

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=10.5),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP", response_time_ms=8.2),
            PortResult(ip="192.168.1.1", port=443, status=PortStatus.OPEN, service="HTTPS", response_time_ms=9.1),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL", response_time_ms=15.3),
            PortResult(ip="192.168.1.1", port=8080, status=PortStatus.CLOSED, response_time_ms=5.0),
            PortResult(ip="192.168.1.2", port=22, status=PortStatus.FILTERED, response_time_ms=3000.0),
        ]

        summary = create_summary(results, 10.5)
        display.display_summary(summary)

        print("\n显示全部结果（按端口排序）:")
        display.display_results_table(results, sort_by="port")

        print("\n显示全部结果（按IP排序）:")
        display.display_results_table(results, sort_by="ip")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_display_open_ports():
    print("\n" + "=" * 60)
    print("测试5.5: 显示开放端口")
    print("=" * 60)

    try:
        display = ResultDisplay(show_progress=False)

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=10.5),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP", response_time_ms=8.2),
            PortResult(ip="192.168.1.1", port=8080, status=PortStatus.CLOSED, response_time_ms=5.0),
        ]

        display.display_open_ports(results)

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_display_high_risk():
    print("\n" + "=" * 60)
    print("测试5.6: 显示高危端口")
    print("=" * 60)

    try:
        display = ResultDisplay(show_progress=False)

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=10.5),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP", response_time_ms=8.2),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL", response_time_ms=15.3),
        ]

        display.display_high_risk_ports(results)

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_display_compact():
    print("\n" + "=" * 60)
    print("测试5.7: 紧凑显示模式")
    print("=" * 60)

    try:
        display = ResultDisplay(show_progress=False)

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=10.5),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP", response_time_ms=8.2),
            PortResult(ip="192.168.1.1", port=443, status=PortStatus.OPEN, service="HTTPS", response_time_ms=9.1),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL", response_time_ms=15.3),
            PortResult(ip="192.168.1.2", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=12.0),
        ]

        display.display_compact(results)

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_progress_tracker():
    print("\n" + "=" * 60)
    print("测试5.8: 进度跟踪器")
    print("=" * 60)

    try:
        tracker = ProgressTracker(total=100)

        for i in range(0, 101, 20):
            tracker.update(20)
            current, total = tracker.get_progress()
            elapsed = tracker.get_elapsed_time()
            remaining = tracker.estimate_remaining_time()
            print(f"  进度: {current}/{total} ({current}%), 已用时: {elapsed:.2f}秒, 预计剩余: {remaining:.2f}秒")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_sort_options():
    print("\n" + "=" * 60)
    print("测试5.9: 排序选项")
    print("=" * 60)

    try:
        display = ResultDisplay(show_progress=False)

        results = [
            PortResult(ip="192.168.1.2", port=80, status=PortStatus.OPEN, service="HTTP", response_time_ms=8.2),
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH", response_time_ms=10.5),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL", response_time_ms=15.3),
            PortResult(ip="192.168.1.1", port=443, status=PortStatus.OPEN, service="HTTPS", response_time_ms=9.1),
        ]

        for sort_by in ["ip", "port", "status", "time", "risk"]:
            print(f"\n  排序方式: {sort_by}")
            display.display_results_table(results, sort_by=sort_by)

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块5 测试套件")
    print("测试内容: 基础结果展示模块")
    print("=" * 60)

    results = []

    results.append(("扫描任务数据类", test_scan_task()))
    results.append(("扫描摘要数据类", test_scan_summary()))
    results.append(("生成扫描摘要", test_create_summary()))
    results.append(("结果展示", test_result_display()))
    results.append(("显示开放端口", test_display_open_ports()))
    results.append(("显示高危端口", test_display_high_risk()))
    results.append(("紧凑显示模式", test_display_compact()))
    results.append(("进度跟踪器", test_progress_tracker()))
    results.append(("排序选项", test_sort_options()))

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
        print("\n模块5 测试全部通过!")
    else:
        print("\n模块5 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
