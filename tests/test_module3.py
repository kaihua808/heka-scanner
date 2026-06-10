import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.port_parser import PortParser, parse_ports, is_valid_port_input
from core.port_scanner import PortScanner, PortStatus, scan_port, PortResult
from core.exceptions import InvalidPortError


def test_port_parser():
    print("\n" + "=" * 60)
    print("测试3.1: 端口解析器")
    print("=" * 60)

    parser = PortParser()

    test_cases = [
        ("1-10", list(range(1, 11)), "范围解析"),
        ("80", [80], "单端口"),
        ("80,443", [80, 443], "多端口逗号分隔"),
        ("21,22,23", [21, 22, 23], "多端口逗号分隔"),
        ("1-5,80,443", [1, 2, 3, 4, 5, 80, 443], "混合模式"),
        ("80-82,443", [80, 81, 82, 443], "范围+单端口"),
        ("all", list(range(1, 65536)), "所有端口"),
        ("common", list(range(1, 1025)), "常用端口"),
        ("top20", [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017], "Top20端口"),
        ("range:1-100", list(range(1, 101)), "带前缀范围"),
        ("1-65535", list(range(1, 65536)), "全范围"),
    ]

    passed = 0
    failed = 0

    for port_input, expected, desc in test_cases:
        try:
            result = parser.parse(port_input)
            if result == expected:
                print(f"  [PASS] {port_input} ({desc}) -> {len(result)}个端口")
                passed += 1
            else:
                print(f"  [FAIL] {port_input} ({desc})")
                print(f"         期望: {expected[:10]}...")
                print(f"         实际: {result[:10]}...")
                failed += 1
        except Exception as e:
            print(f"  [FAIL] {port_input} ({desc}) 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_port_validation():
    print("\n" + "=" * 60)
    print("测试3.2: 端口验证")
    print("=" * 60)

    parser = PortParser()

    invalid_cases = [
        "",
        "   ",
        "0",
        "65536",
        "-1",
        "abc",
        "80abc",
        "80-79",
        "1-65536",
    ]

    passed = 0
    failed = 0

    for invalid_input in invalid_cases:
        try:
            result = parser.parse(invalid_input)
            print(f"  [FAIL] '{invalid_input}' 应该抛出异常")
            failed += 1
        except InvalidPortError as e:
            print(f"  [PASS] '{invalid_input}' 正确拒绝: {e.reason[:40]}...")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] '{invalid_input}' 抛出错误异常: {type(e).__name__}")
            failed += 1

    valid_cases = ["1", "80", "443", "65535", "1-100"]
    for valid_input in valid_cases:
        try:
            result = parser.parse(valid_input)
            print(f"  [PASS] '{valid_input}' 正确接受 -> {len(result)}个端口")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] '{valid_input}' 不应抛出异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_port_scanner_basic():
    print("\n" + "=" * 60)
    print("测试3.3: 端口扫描器基础功能")
    print("=" * 60)

    scanner = PortScanner(timeout=2.0)

    test_hosts = [
        ("127.0.0.1", 80, "本机HTTP"),
        ("127.0.0.1", 443, "本机HTTPS"),
        ("127.0.0.1", 22, "本机SSH"),
    ]

    passed = 0
    failed = 0

    for ip, port, desc in test_hosts:
        try:
            result = scanner.scan(ip, port)
            print(f"  [INFO] {ip}:{port} ({desc}) -> {result.status.value}, 耗时:{result.response_time_ms:.2f}ms")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {ip}:{port} ({desc}) 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_port_scanner_status():
    print("\n" + "=" * 60)
    print("测试3.4: 端口状态判定")
    print("=" * 60)

    scanner = PortScanner(timeout=2.0)

    test_cases = [
        ("127.0.0.1", 80, "本机Web"),
        ("127.0.0.1", 443, "本机HTTPS"),
        ("127.0.0.1", 22, "本机SSH"),
        ("127.0.0.1", 3306, "本机MySQL"),
        ("127.0.0.1", 5432, "本机PostgreSQL"),
        ("127.0.0.1", 6379, "本机Redis"),
        ("127.0.0.1", 27017, "本机MongoDB"),
    ]

    passed = 0
    failed = 0

    for ip, port, desc in test_cases:
        try:
            result = scanner.scan(ip, port)
            status_str = result.status.value
            time_str = f"{result.response_time_ms:.2f}ms"
            print(f"  [INFO] {ip}:{port} ({desc}) -> {status_str}, 耗时:{time_str}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {ip}:{port} ({desc}) 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_port_scanner_retry():
    print("\n" + "=" * 60)
    print("测试3.5: 重试机制")
    print("=" * 60)

    scanner = PortScanner(timeout=1.0, retry_count=2)

    try:
        result = scanner.scan("192.168.1.1", 9999)
        print(f"  [INFO] 扫描结果: {result.status.value}")
        print(f"  [INFO] 重试次数: {result.retry_count}")
        print(f"  [PASS] 重试机制正常工作")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_scan_port_function():
    print("\n" + "=" * 60)
    print("测试3.6: 快捷函数")
    print("=" * 60)

    try:
        result = scan_port("127.0.0.1", 80)
        print(f"  [PASS] scan_port函数正常 -> {result.status.value}")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_port_result_dataclass():
    print("\n" + "=" * 60)
    print("测试3.7: 结果数据结构")
    print("=" * 60)

    try:
        result = PortResult(
            ip="192.168.1.1",
            port=80,
            status=PortStatus.OPEN,
            service="HTTP",
            response_time_ms=12.5,
            retry_count=0
        )

        result_dict = result.to_dict()
        print(f"  [PASS] to_dict() -> {result_dict}")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_batch_scan():
    print("\n" + "=" * 60)
    print("测试3.8: 批量扫描")
    print("=" * 60)

    scanner = PortScanner(timeout=1.0)
    ports = [21, 22, 23, 80, 443, 3306, 3389]

    start_time = time.time()
    results = [scanner.scan("127.0.0.1", port) for port in ports]
    elapsed = time.time() - start_time

    open_count = sum(1 for r in results if r.status == PortStatus.OPEN)
    closed_count = sum(1 for r in results if r.status == PortStatus.CLOSED)

    print(f"  [INFO] 扫描{len(ports)}个端口，耗时:{elapsed:.2f}秒")
    print(f"  [INFO] 开放:{open_count}, 关闭:{closed_count}")

    for r in results:
        print(f"    {r.ip}:{r.port} -> {r.status.value} ({r.response_time_ms:.2f}ms)")

    return True


def main():
    print("\n" + "=" * 60)
    print("模块3 测试套件")
    print("测试内容: 端口探测核心模块")
    print("=" * 60)

    results = []

    results.append(("端口解析器", test_port_parser()))
    results.append(("端口验证", test_port_validation()))
    results.append(("端口扫描器基础", test_port_scanner_basic()))
    results.append(("端口状态判定", test_port_scanner_status()))
    results.append(("重试机制", test_port_scanner_retry()))
    results.append(("快捷函数", test_scan_port_function()))
    results.append(("结果数据结构", test_port_result_dataclass()))
    results.append(("批量扫描", test_batch_scan()))

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
        print("\n模块3 测试全部通过!")
    else:
        print("\n模块3 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
