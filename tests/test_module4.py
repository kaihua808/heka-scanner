import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.service_detector import (
    ServiceDetector, RiskLevel,
    detect_service, get_risk_level, get_port_info
)


def test_service_detection():
    print("\n" + "=" * 60)
    print("测试4.1: 服务识别")
    print("=" * 60)

    detector = ServiceDetector()

    test_cases = [
        (21, "FTP"),
        (22, "SSH"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (27017, "MongoDB"),
        (9999, "Unknown"),
    ]

    passed = 0
    failed = 0

    for port, expected in test_cases:
        result = detector.detect(port)
        if result == expected:
            print(f"  [PASS] 端口{port} -> {result}")
            passed += 1
        else:
            print(f"  [FAIL] 端口{port} -> {result}, 期望: {expected}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_risk_level():
    print("\n" + "=" * 60)
    print("测试4.2: 风险等级判定")
    print("=" * 60)

    detector = ServiceDetector()

    test_cases = [
        (22, RiskLevel.HIGH, "SSH"),
        (3306, RiskLevel.HIGH, "MySQL"),
        (3389, RiskLevel.HIGH, "RDP"),
        (6379, RiskLevel.HIGH, "Redis"),
        (80, RiskLevel.MEDIUM, "HTTP"),
        (443, RiskLevel.MEDIUM, "HTTPS"),
        (8080, RiskLevel.MEDIUM, "HTTP-Proxy"),
        (9999, RiskLevel.NONE, "Unknown"),
    ]

    passed = 0
    failed = 0

    for port, expected_risk, service in test_cases:
        risk = detector.get_risk_level(port)
        detected_service = detector.get_service_name(port)

        if risk == expected_risk and detected_service == service:
            print(f"  [PASS] 端口{port}({service}) -> {risk.value}")
            passed += 1
        else:
            print(f"  [FAIL] 端口{port} -> 风险:{risk.value}, 服务:{detected_service}")
            print(f"         期望: 风险:{expected_risk.value}, 服务:{service}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_risk_emoji():
    print("\n" + "=" * 60)
    print("测试4.3: 风险等级图标")
    print("=" * 60)

    test_cases = [
        (RiskLevel.HIGH, "[HIGH]"),
        (RiskLevel.MEDIUM, "[MED]"),
        (RiskLevel.LOW, "[LOW]"),
        (RiskLevel.NONE, "[NONE]"),
    ]

    passed = 0
    failed = 0

    for risk_level, expected_emoji in test_cases:
        emoji = ServiceDetector.get_risk_emoji(risk_level)
        if emoji == expected_emoji:
            print(f"  [PASS] {risk_level.value} -> {emoji}")
            passed += 1
        else:
            print(f"  [FAIL] {risk_level.value} -> {emoji}, 期望: {expected_emoji}")
            failed += 1

    print(f"\n测试结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_risk_description():
    print("\n" + "=" * 60)
    print("测试4.4: 风险描述")
    print("=" * 60)

    detector = ServiceDetector()

    port = 22
    description = detector.get_risk_description(port)
    print(f"  端口{port}(SSH): {description}")

    port = 80
    description = detector.get_risk_description(port)
    print(f"  端口{port}(HTTP): {description}")

    return True


def test_format_risk_info():
    print("\n" + "=" * 60)
    print("测试4.5: 风险信息格式化")
    print("=" * 60)

    detector = ServiceDetector()

    test_ports = [22, 80, 9999]

    for port in test_ports:
        info = detector.format_risk_info(port)
        print(f"  端口{port}: {info}")

    return True


def test_get_port_info():
    print("\n" + "=" * 60)
    print("测试4.6: 端口信息获取")
    print("=" * 60)

    test_ports = [22, 80, 3306, 9999]

    for port in test_ports:
        info = get_port_info(port)
        print(f"  端口{port}: {info}")

    return True


def test_search_service():
    print("\n" + "=" * 60)
    print("测试4.7: 服务搜索")
    print("=" * 60)

    detector = ServiceDetector()

    keywords = ["http", "sql", "ssh", "mysql"]

    for keyword in keywords:
        results = detector.search_service(keyword)
        print(f"  搜索'{keyword}': {results}")

    return True


def test_get_services_by_category():
    print("\n" + "=" * 60)
    print("测试4.8: 按类别获取服务")
    print("=" * 60)

    detector = ServiceDetector()
    categories = detector.get_services_by_category()

    for category, ports in categories.items():
        print(f"  {category}: {ports}")

    return True


def test_convenience_functions():
    print("\n" + "=" * 60)
    print("测试4.9: 快捷函数")
    print("=" * 60)

    try:
        service = detect_service(3306)
        print(f"  detect_service(3306) -> {service}")

        risk = get_risk_level(22)
        print(f"  get_risk_level(22) -> {risk}")

        info = get_port_info(443)
        print(f"  get_port_info(443) -> {info}")

        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块4 测试套件")
    print("测试内容: 服务识别与风险评估模块")
    print("=" * 60)

    results = []

    results.append(("服务识别", test_service_detection()))
    results.append(("风险等级判定", test_risk_level()))
    results.append(("风险图标", test_risk_emoji()))
    results.append(("风险描述", test_risk_description()))
    results.append(("信息格式化", test_format_risk_info()))
    results.append(("端口信息", test_get_port_info()))
    results.append(("服务搜索", test_search_service()))
    results.append(("服务分类", test_get_services_by_category()))
    results.append(("快捷函数", test_convenience_functions()))

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
        print("\n模块4 测试全部通过!")
    else:
        print("\n模块4 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
