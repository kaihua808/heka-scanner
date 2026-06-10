import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ip_validator import IPValidator
from core.exceptions import InvalidIPError, ComplianceViolationError
from core.logger import Logger


def test_single_ip():
    print("\n" + "=" * 60)
    print("测试2.1: 单IP输入验证")
    print("=" * 60)

    validator = IPValidator()

    test_cases = [
        ("192.168.1.1", True, None),
        ("192.168.1.100", True, None),
        ("192.168.0.1", True, None),
        ("192.168.255.254", True, None),
        ("127.0.0.1", True, None),
        ("127.0.0.2", True, None),
        ("127.255.255.255", True, None),
        ("10.0.0.1", False, "公网IP地址"),
        ("8.8.8.8", False, "公网IP地址"),
        ("114.114.114.114", False, "公网IP地址"),
        ("1.1.1.1", False, "公网IP地址"),
    ]

    passed = 0
    failed = 0

    for ip, should_pass, expected_reason in test_cases:
        try:
            result = validator.validate(ip)
            if should_pass:
                print(f"  [PASS] {ip} -> {result}")
                passed += 1
            else:
                print(f"  [FAIL] {ip} 应该被拦截，但通过了")
                failed += 1
        except ComplianceViolationError as e:
            if not should_pass:
                print(f"  [PASS] {ip} 被正确拦截: {e.reason}")
                passed += 1
            else:
                print(f"  [FAIL] {ip} 不应被拦截: {e}")
                failed += 1
        except Exception as e:
            print(f"  [FAIL] {ip} 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_localhost():
    print("\n" + "=" * 60)
    print("测试2.2: 本机地址验证")
    print("=" * 60)

    validator = IPValidator()

    test_cases = [
        ("localhost", ['127.0.0.1']),
        ("本机", ['127.0.0.1']),
        ("LOCALHOST", ['127.0.0.1']),
    ]

    passed = 0
    failed = 0

    for input_val, expected in test_cases:
        try:
            result = validator.validate(input_val)
            if result == expected:
                print(f"  [PASS] {input_val} -> {result}")
                passed += 1
            else:
                print(f"  [FAIL] {input_val} -> {result}, 期望: {expected}")
                failed += 1
        except Exception as e:
            print(f"  [FAIL] {input_val} 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_cidr():
    print("\n" + "=" * 60)
    print("测试2.3: CIDR网段验证")
    print("=" * 60)

    validator = IPValidator()

    test_cases = [
        ("192.168.1.0/24", True, 254),
        ("192.168.0.0/24", True, 254),
        ("192.168.10.0/24", True, 254),
        ("127.0.0.0/8", True, 16777214),
        ("127.0.0.0/24", True, 254),
        ("10.0.0.0/24", False, None),
        ("8.8.8.0/24", False, None),
    ]

    passed = 0
    failed = 0

    for cidr, should_pass, expected_count in test_cases:
        try:
            result = validator.validate(cidr)
            if should_pass:
                if expected_count and len(result) == expected_count:
                    print(f"  [PASS] {cidr} -> {len(result)} IPs")
                    passed += 1
                else:
                    print(f"  [FAIL] {cidr} 数量不符: {len(result)}, 期望: {expected_count}")
                    failed += 1
            else:
                print(f"  [FAIL] {cidr} 应该被拦截")
                failed += 1
        except ComplianceViolationError as e:
            if not should_pass:
                print(f"  [PASS] {cidr} 被正确拦截: {e.reason[:50]}...")
                passed += 1
            else:
                print(f"  [FAIL] {cidr} 不应被拦截: {e}")
                failed += 1
        except Exception as e:
            print(f"  [FAIL] {cidr} 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_range():
    print("\n" + "=" * 60)
    print("测试2.4: IP范围验证")
    print("=" * 60)

    validator = IPValidator()

    test_cases = [
        ("192.168.1.1-192.168.1.10", True, 10),
        ("192.168.1.1-192.168.1.100", True, 100),
        ("127.0.0.1-127.0.0.5", True, 5),
        ("192.168.1.1-192.168.1.200", True, 200),
        ("10.0.0.1-10.0.0.10", False, None),
    ]

    passed = 0
    failed = 0

    for ip_range, should_pass, expected_count in test_cases:
        try:
            result = validator.validate(ip_range)
            if should_pass:
                if expected_count and len(result) == expected_count:
                    print(f"  [PASS] {ip_range} -> {len(result)} IPs")
                    passed += 1
                else:
                    print(f"  [FAIL] {ip_range} 数量不符: {len(result)}, 期望: {expected_count}")
                    failed += 1
            else:
                print(f"  [FAIL] {ip_range} 应该被拦截")
                failed += 1
        except ComplianceViolationError as e:
            if not should_pass:
                print(f"  [PASS] {ip_range} 被正确拦截: {e.reason[:50]}...")
                passed += 1
            else:
                print(f"  [FAIL] {ip_range} 不应被拦截: {e}")
                failed += 1
        except Exception as e:
            print(f"  [FAIL] {ip_range} 异常: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_invalid_input():
    print("\n" + "=" * 60)
    print("测试2.5: 无效输入验证")
    print("=" * 60)

    validator = IPValidator()

    test_cases = [
        "",
        "   ",
        "999.999.999.999",
        "192.168.1",
        "192.168.1.1.1",
        "abc.def.ghi.jkl",
        "192.168.1.1-192.168.1.0",
        "192.168.1.0/33",
    ]

    passed = 0
    failed = 0

    for invalid_input in test_cases:
        try:
            result = validator.validate(invalid_input)
            print(f"  [FAIL] '{invalid_input}' 应该抛出异常")
            failed += 1
        except (InvalidIPError, ComplianceViolationError) as e:
            print(f"  [PASS] '{invalid_input}' 正确抛出异常: {type(e).__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] '{invalid_input}' 抛出错误异常: {type(e).__name__}: {e}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_compliance_logger():
    print("\n" + "=" * 60)
    print("测试2.6: 合规违规日志记录")
    print("=" * 60)

    log_config = {
        'level': 'INFO',
        'console': True,
        'file': './logs/compliance_test.log'
    }
    logger = Logger("ComplianceTest", log_config)
    validator = IPValidator(logger)

    try:
        validator.validate("8.8.8.8")
        print("  [FAIL] 应该抛出合规违规异常")
        return False
    except ComplianceViolationError as e:
        print(f"  [PASS] 合规违规异常已抛出")
        print(f"         违规IP: {e.ip}")
        print(f"         违规原因: {e.reason}")
        return True
    except Exception as e:
        print(f"  [FAIL] 抛出错误异常类型: {type(e).__name__}")
        return False


def test_get_network_info():
    print("\n" + "=" * 60)
    print("测试2.7: 网段信息查询")
    print("=" * 60)

    validator = IPValidator()

    try:
        info1 = validator.get_network_info("192.168.1.0/24")
        print(f"  网段信息: {info1}")

        info2 = validator.get_network_info("192.168.1.1")
        print(f"  单IP信息: {info2}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_is_valid_function():
    print("\n" + "=" * 60)
    print("测试2.8: is_valid快速验证函数")
    print("=" * 60)

    from core.ip_validator import is_valid_ip

    test_cases = [
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("8.8.8.8", False),
        ("invalid", False),
    ]

    passed = 0
    failed = 0

    for ip, expected in test_cases:
        is_valid, error = is_valid_ip(ip)
        if is_valid == expected:
            print(f"  [PASS] {ip} -> {is_valid}")
            passed += 1
        else:
            print(f"  [FAIL] {ip} -> {is_valid}, 期望: {expected}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def main():
    print("\n" + "=" * 60)
    print("模块2 测试套件")
    print("测试内容: IP合规校验模块")
    print("=" * 60)

    results = []

    results.append(("单IP输入验证", test_single_ip()))
    results.append(("本机地址验证", test_localhost()))
    results.append(("CIDR网段验证", test_cidr()))
    results.append(("IP范围验证", test_range()))
    results.append(("无效输入验证", test_invalid_input()))
    results.append(("合规违规日志", test_compliance_logger()))
    results.append(("网段信息查询", test_get_network_info()))
    results.append(("is_valid函数", test_is_valid_function()))

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
        print("\n模块2 测试全部通过!")
    else:
        print("\n模块2 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
