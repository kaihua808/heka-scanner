import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from output.risk_assessment import (
    RiskAnnotator, ConflictDetector, HeatmapGenerator,
    ColorCode, RiskAnnotation, ConflictInfo, HeatmapEntry,
    create_risk_report
)
from core.port_scanner import PortResult, PortStatus
from core.service_detector import RiskLevel


def test_risk_annotator():
    print("\n" + "=" * 60)
    print("测试9.1: 风险标注器")
    print("=" * 60)

    try:
        annotator = RiskAnnotator()

        test_ports = [22, 80, 443, 3306, 9999]

        for port in test_ports:
            color = annotator.get_color_for_port(port)
            weight = annotator.get_risk_weight(port)
            print(f"  端口{port}: 颜色={color.value}, 权重={weight}")

        print("  [PASS] 风险标注器")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_annotate_results():
    print("\n" + "=" * 60)
    print("测试9.2: 标注扫描结果")
    print("=" * 60)

    try:
        annotator = RiskAnnotator()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.1", port=8080, status=PortStatus.CLOSED),
        ]

        annotations = annotator.annotate_results(results)
        print(f"  标注数量: {len(annotations)}")

        for ann in annotations:
            print(f"    端口{ann.port}({ann.service}): {ann.risk_level.value}, {ann.color.value}")

        print("  [PASS] 标注扫描结果")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_risk_summary():
    print("\n" + "=" * 60)
    print("测试9.3: 风险摘要")
    print("=" * 60)

    try:
        annotator = RiskAnnotator()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.1", port=3389, status=PortStatus.OPEN, service="RDP"),
        ]

        summary = annotator.get_risk_summary(results)
        print(f"  风险摘要: {summary}")

        risk_score = annotator.calculate_network_risk_score(results)
        print(f"  风险评分: {risk_score}")

        print("  [PASS] 风险摘要")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_conflict_detector():
    print("\n" + "=" * 60)
    print("测试9.4: 冲突检测器")
    print("=" * 60)

    try:
        detector = ConflictDetector()

        results = [
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.2", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=443, status=PortStatus.OPEN, service="HTTPS"),
        ]

        detector.mark_port_used(80, "192.168.1.1")
        detector.mark_port_used(80, "192.168.1.2")

        conflicts = detector.detect_port_conflicts(results)
        print(f"  检测到冲突: {len(conflicts)}")

        for c in conflicts:
            print(f"    类型: {c.conflict_type}, IP: {c.ip}, 端口: {c.port}")

        print("  [PASS] 冲突检测器")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_heatmap_generator():
    print("\n" + "=" * 60)
    print("测试9.5: 热力图生成器")
    print("=" * 60)

    try:
        generator = HeatmapGenerator()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.2", port=3389, status=PortStatus.OPEN, service="RDP"),
        ]

        heatmap = generator.generate_heatmap(results)
        print(f"  热力条目数: {len(heatmap)}")

        for entry in heatmap:
            print(f"    {entry.ip}:{entry.port} - {entry.risk_level.value}, {entry.color.value}, 权重:{entry.weight}")

        stats = generator.get_heatmap_stats(heatmap)
        print(f"  热力统计: {stats}")

        print("  [PASS] 热力图生成器")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_group_heatmap():
    print("\n" + "=" * 60)
    print("测试9.6: 热力图分组")
    print("=" * 60)

    try:
        generator = HeatmapGenerator()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.2", port=3306, status=PortStatus.OPEN, service="MySQL"),
        ]

        heatmap = generator.generate_heatmap(results)

        by_ip = generator.group_by_ip(heatmap)
        print(f"  按IP分组: {len(by_ip)} 组")
        for ip, entries in by_ip.items():
            print(f"    {ip}: {len(entries)} 个端口")

        by_risk = generator.group_by_risk(heatmap)
        print(f"  按风险分组: {len(by_risk)} 级")
        for risk, entries in by_risk.items():
            print(f"    {risk.value}: {len(entries)} 个")

        print("  [PASS] 热力图分组")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_render_text_heatmap():
    print("\n" + "=" * 60)
    print("测试9.7: 文本热力图渲染")
    print("=" * 60)

    try:
        generator = HeatmapGenerator()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.2", port=3389, status=PortStatus.OPEN, service="RDP"),
            PortResult(ip="192.168.1.2", port=443, status=PortStatus.OPEN, service="HTTPS"),
        ]

        heatmap = generator.generate_heatmap(results)
        text = generator.render_text_heatmap(heatmap)

        print("  热力图:")
        for line in text.split("\n"):
            print(f"    {line}")

        print("  [PASS] 文本热力图渲染")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_create_risk_report():
    print("\n" + "=" * 60)
    print("测试9.8: 创建风险报告")
    print("=" * 60)

    try:
        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.1", port=443, status=PortStatus.OPEN, service="HTTPS"),
            PortResult(ip="192.168.1.2", port=3389, status=PortStatus.OPEN, service="RDP"),
        ]

        report = create_risk_report(results)

        print(f"  开放端口总数: {report['total_open_ports']}")
        print(f"  风险摘要: {report['risk_summary']}")
        print(f"  风险评分: {report['risk_score']}")
        print(f"  高危端口数: {len(report['high_risk_ports'])}")
        print(f"  冲突数: {len(report['conflicts'])}")

        print("  [PASS] 创建风险报告")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_high_risk_ports():
    print("\n" + "=" * 60)
    print("测试9.9: 高危端口筛选")
    print("=" * 60)

    try:
        annotator = RiskAnnotator()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.1", port=3389, status=PortStatus.OPEN, service="RDP"),
            PortResult(ip="192.168.1.1", port=8080, status=PortStatus.CLOSED),
        ]

        high_risk = annotator.get_high_risk_ports(results)
        print(f"  高危端口数: {len(high_risk)}")
        for r in high_risk:
            print(f"    {r.ip}:{r.port} ({r.service})")

        medium_risk = annotator.get_medium_risk_ports(results)
        print(f"  中危端口数: {len(medium_risk)}")

        print("  [PASS] 高危端口筛选")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_color_codes():
    print("\n" + "=" * 60)
    print("测试9.10: 颜色代码枚举")
    print("=" * 60)

    try:
        print(f"  RED: {ColorCode.RED.value}")
        print(f"  YELLOW: {ColorCode.YELLOW.value}")
        print(f"  GREEN: {ColorCode.GREEN.value}")
        print(f"  BLUE: {ColorCode.BLUE.value}")
        print(f"  WHITE: {ColorCode.WHITE.value}")
        print(f"  GRAY: {ColorCode.GRAY.value}")

        print("  [PASS] 颜色代码枚举")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块9 测试套件")
    print("测试内容: 风险评估与热力标注")
    print("=" * 60)

    results = []

    results.append(("风险标注器", test_risk_annotator()))
    results.append(("标注扫描结果", test_annotate_results()))
    results.append(("风险摘要", test_risk_summary()))
    results.append(("冲突检测器", test_conflict_detector()))
    results.append(("热力图生成器", test_heatmap_generator()))
    results.append(("热力图分组", test_group_heatmap()))
    results.append(("文本热力图渲染", test_render_text_heatmap()))
    results.append(("创建风险报告", test_create_risk_report()))
    results.append(("高危端口筛选", test_high_risk_ports()))
    results.append(("颜色代码枚举", test_color_codes()))

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
        print("\n模块9 测试全部通过!")
    else:
        print("\n模块9 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
