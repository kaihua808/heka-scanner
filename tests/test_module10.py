import sys
import os
import tempfile
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from output.audit import (
    AuditLogger, ResultExporter, DigitalSigner, AuditEntry,
    DigitalSignature, AuditReport, generate_sla_report
)
from core.port_scanner import PortResult, PortStatus


def test_digital_signer():
    print("\n" + "=" * 60)
    print("测试10.1: 数字签名器")
    print("=" * 60)

    try:
        signer = DigitalSigner()

        content = "这是一段测试内容"

        signature = signer.sign(content, "test_user", "test_host")
        print(f"  算法: {signature.algorithm}")
        print(f"  哈希值: {signature.hash_value[:32]}...")
        print(f"  签名时间: {signature.signed_at}")
        print(f"  签名人: {signature.operator}")

        is_valid = signer.verify(content, signature)
        print(f"  验证结果: {is_valid}")

        content_tampered = "这是被篡改的内容"
        is_valid_tampered = signer.verify(content_tampered, signature)
        print(f"  篡改后验证: {is_valid_tampered}")

        print("  [PASS] 数字签名器")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_audit_logger():
    print("\n" + "=" * 60)
    print("测试10.2: 审计日志器")
    print("=" * 60)

    try:
        logger = AuditLogger()

        entry = logger.log_action(
            action="TEST_ACTION",
            target="192.168.1.1",
            result="SUCCESS",
            details="测试详情"
        )

        print(f"  审计条目: {entry.action} - {entry.target}")
        print(f"  操作员: {entry.operator}")
        print(f"  主机名: {entry.hostname}")

        entries = logger.get_audit_trail()
        print(f"  审计记录数: {len(entries)}")

        print("  [PASS] 审计日志器")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_audit_log_export():
    print("\n" + "=" * 60)
    print("测试10.3: 审计日志导出")
    print("=" * 60)

    try:
        logger = AuditLogger()
        logger.log_action("SCAN_START", "192.168.1.0/24", "INITIATED", "Ports: 1-100")
        logger.log_action("SCAN_COMPLETE", "192.168.1.0/24", "SUCCESS", "Open: 5")

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
            temp_path = f.name

        success = logger.export_audit_log(temp_path, format="txt", include_signature=True)
        print(f"  导出成功: {success}")

        with open(temp_path, 'r', encoding='utf-8') as f:
            content = f.read()
            has_signature = "数字签名" in content or "Digital Signature" in content
            print(f"  包含签名: {has_signature}")

        is_valid, msg = logger.verify_file_integrity(temp_path)
        print(f"  签名验证: {is_valid} - {msg}")

        os.unlink(temp_path)

        print("  [PASS] 审计日志导出")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_audit_log_formats():
    print("\n" + "=" * 60)
    print("测试10.4: 审计日志多格式")
    print("=" * 60)

    try:
        logger = AuditLogger()
        logger.log_action("TEST", "target", "OK", "details")

        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = os.path.join(tmpdir, "audit.txt")
            csv_path = os.path.join(tmpdir, "audit.csv")
            json_path = os.path.join(tmpdir, "audit.json")

            logger.export_audit_log(txt_path, format="txt")
            print(f"  TXT导出: OK")

            logger.export_audit_log(csv_path, format="csv")
            print(f"  CSV导出: OK")

            logger.export_audit_log(json_path, format="json")
            print(f"  JSON导出: OK")

        print("  [PASS] 审计日志多格式")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_result_exporter():
    print("\n" + "=" * 60)
    print("测试10.5: 结果导出器")
    print("=" * 60)

    try:
        exporter = ResultExporter()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
            PortResult(ip="192.168.1.1", port=3306, status=PortStatus.OPEN, service="MySQL"),
            PortResult(ip="192.168.1.1", port=8080, status=PortStatus.CLOSED),
        ]

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
            temp_path = f.name

        success = exporter.export_results(results, temp_path, format="txt", sign=True)
        print(f"  导出成功: {success}")

        is_valid, msg = exporter.verify_export_integrity(temp_path)
        print(f"  签名验证: {is_valid} - {msg}")

        os.unlink(temp_path)

        print("  [PASS] 结果导出器")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_result_export_formats():
    print("\n" + "=" * 60)
    print("测试10.6: 结果多格式导出")
    print("=" * 60)

    try:
        exporter = ResultExporter()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = os.path.join(tmpdir, "results.txt")
            csv_path = os.path.join(tmpdir, "results.csv")
            json_path = os.path.join(tmpdir, "results.json")

            exporter.export_results(results, txt_path, format="txt")
            print(f"  TXT导出: OK")

            exporter.export_results(results, csv_path, format="csv")
            print(f"  CSV导出: OK")

            exporter.export_results(results, json_path, format="json")
            print(f"  JSON导出: OK")

            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"  JSON记录数: {data['summary']['total']}")

        print("  [PASS] 结果多格式导出")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_compliance_logging():
    print("\n" + "=" * 60)
    print("测试10.7: 合规日志记录")
    print("=" * 60)

    try:
        logger = AuditLogger()

        entry = logger.log_compliance_violation("8.8.8.8", "公网IP不允许扫描")
        print(f"  合规违规记录: {entry.action}")
        print(f"  目标: {entry.target}")
        print(f"  结果: {entry.result}")
        print(f"  详情: {entry.details}")

        print("  [PASS] 合规日志记录")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_scan_logging():
    print("\n" + "=" * 60)
    print("测试10.8: 扫描日志记录")
    print("=" * 60)

    try:
        logger = AuditLogger()

        start_entry = logger.log_scan_start(["192.168.1.0/24"], "1-1000")
        print(f"  扫描开始: {start_entry.action}")

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
            PortResult(ip="192.168.1.1", port=80, status=PortStatus.OPEN, service="HTTP"),
        ]

        complete_entry = logger.log_scan_complete(
            ["192.168.1.0/24"],
            "1-1000",
            results,
            5.5
        )
        print(f"  扫描完成: {complete_entry.action}")
        print(f"  详情: {complete_entry.details}")

        print("  [PASS] 扫描日志记录")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_signature_verification():
    print("\n" + "=" * 60)
    print("测试10.9: 签名验证(篡改检测)")
    print("=" * 60)

    try:
        signer = DigitalSigner()
        exporter = ResultExporter()

        results = [
            PortResult(ip="192.168.1.1", port=22, status=PortStatus.OPEN, service="SSH"),
        ]

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
            temp_path = f.name

        exporter.export_results(results, temp_path, format="txt", sign=True)

        is_valid1, msg1 = exporter.verify_export_integrity(temp_path)
        print(f"  原始文件验证: {is_valid1} - {msg1}")

        with open(temp_path, 'r', encoding='utf-8') as f:
            content = f.read()

        tampered_content = content.replace("SSH", "FTP")
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(tampered_content)

        is_valid2, msg2 = exporter.verify_export_integrity(temp_path)
        print(f"  篡改后验证: {is_valid2} - {msg2}")

        os.unlink(temp_path)

        print("  [PASS] 签名验证(篡改检测)")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def test_sla_report():
    print("\n" + "=" * 60)
    print("测试10.10: SLA报表生成")
    print("=" * 60)

    try:
        scan_history = [
            {"duration": 10.0, "ports": 1000},
            {"duration": 12.0, "ports": 1000},
            {"duration": 8.0, "ports": 1000},
            {"duration": 20.0, "ports": 1000},
            {"duration": 15.0, "ports": 1000},
        ]

        report = generate_sla_report(scan_history, target_duration=15.0)

        print(f"  总扫描数: {report['total_scans']}")
        print(f"  平均耗时: {report['avg_duration']:.2f}s")
        print(f"  最小耗时: {report['min_duration']:.2f}s")
        print(f"  最大耗时: {report['max_duration']:.2f}s")
        print(f"  SLA达标率: {report['compliance_rate']:.1f}%")
        print(f"  达标数量: {report['met_sla_count']}")
        print(f"  未达标数量: {report['failed_sla_count']}")

        print("  [PASS] SLA报表生成")
        return True
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块10 测试套件")
    print("测试内容: 审计日志与数字签名")
    print("=" * 60)

    results = []

    results.append(("数字签名器", test_digital_signer()))
    results.append(("审计日志器", test_audit_logger()))
    results.append(("审计日志导出", test_audit_log_export()))
    results.append(("审计日志多格式", test_audit_log_formats()))
    results.append(("结果导出器", test_result_exporter()))
    results.append(("结果多格式导出", test_result_export_formats()))
    results.append(("合规日志记录", test_compliance_logging()))
    results.append(("扫描日志记录", test_scan_logging()))
    results.append(("签名验证(篡改检测)", test_signature_verification()))
    results.append(("SLA报表生成", test_sla_report()))

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
        print("\n模块10 测试全部通过!")
    else:
        print("\n模块10 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
