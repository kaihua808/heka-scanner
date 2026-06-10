import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_loader import ConfigLoader
from core.logger import Logger
from core.exceptions import (
    ComplianceViolationError,
    InvalidIPError,
    InvalidPortError,
    ConfigError
)


def test_config_loader():
    print("\n" + "=" * 60)
    print("测试配置加载模块")
    print("=" * 60)
    
    try:
        config = ConfigLoader()
        
        print("\n[PASS] 配置文件加载成功")
        
        print(f"\n扫描器名称: {config.get('scanner.name')}")
        print(f"扫描器版本: {config.get('scanner.version')}")
        
        print(f"\n默认线程数: {config.get('scan.default_threads')}")
        print(f"最大线程数: {config.get('scan.max_threads')}")
        print(f"超时时间: {config.get('scan.timeout')}秒")
        
        print(f"\n允许的网段:")
        for network in config.get('compliance.allowed_networks', []):
            print(f"  - {network}")
        
        print(f"\n合规严格模式: {config.get('compliance.strict_mode')}")
        print(f"拦截公网IP: {config.get('compliance.block_public_ip')}")
        
        print("\n已知服务端口:")
        known_ports = config.get('services.known_ports', {})
        for port, service in list(known_ports.items())[:5]:
            print(f"  {port}: {service}")
        print(f"  ... 共 {len(known_ports)} 个已知服务")
        
        print("\n高危端口列表:")
        high_risk = config.get('risk.high_risk_ports', [])
        print(f"  {high_risk}")
        
        config.validate()
        print("\n[PASS] 配置验证通过")
        
        return True
        
    except Exception as e:
        print(f"\n[FAIL] 配置加载失败: {e}")
        return False


def test_logger():
    print("\n" + "=" * 60)
    print("测试日志模块")
    print("=" * 60)
    
    try:
        log_config = {
            'level': 'DEBUG',
            'format': '%(asctime)s - %(levelname)s - %(message)s',
            'file': './logs/test.log',
            'console': True
        }
        logger = Logger("TestScanner", log_config)
        
        print("\n[PASS] 日志模块初始化成功")
        
        print("\n测试各级别日志输出:")
        logger.debug("这是一条DEBUG日志")
        logger.info("这是一条INFO日志")
        logger.warning("这是一条WARNING日志")
        logger.error("这是一条ERROR日志")
        
        print("\n测试合规违规日志:")
        logger.compliance_violation("8.8.8.8", "公网IP地址，不在允许的扫描范围内")
        
        print("\n测试扫描日志:")
        logger.scan_start("192.168.1.1", "1-1000")
        logger.port_result("192.168.1.1", 80, "open", "HTTP", 12.5)
        logger.scan_end(5.23, 10, 980, 10)
        
        print("\n[PASS] 日志模块测试通过")
        
        return True
        
    except Exception as e:
        print(f"\n[FAIL] 日志模块测试失败: {e}")
        return False


def test_exceptions():
    print("\n" + "=" * 60)
    print("测试异常模块")
    print("=" * 60)
    
    try:
        print("\n测试合规违规异常:")
        try:
            raise ComplianceViolationError("8.8.8.8", "公网IP地址")
        except ComplianceViolationError as e:
            print(f"  捕获异常: {e}")
            print(f"  违规IP: {e.ip}")
            print(f"  违规原因: {e.reason}")
        
        print("\n测试无效IP异常:")
        try:
            raise InvalidIPError("999.999.999.999", "IP格式无效")
        except InvalidIPError as e:
            print(f"  捕获异常: {e}")
        
        print("\n测试无效端口异常:")
        try:
            raise InvalidPortError("99999", "端口超出有效范围")
        except InvalidPortError as e:
            print(f"  捕获异常: {e}")
        
        print("\n[PASS] 异常模块测试通过")
        
        return True
        
    except Exception as e:
        print(f"\n[FAIL] 异常模块测试失败: {e}")
        return False


def main():
    print("\n" + "=" * 60)
    print("模块1 测试套件")
    print("测试内容: 项目骨架 + 配置模块")
    print("=" * 60)
    
    results = []
    
    results.append(("配置加载模块", test_config_loader()))
    results.append(("日志模块", test_logger()))
    results.append(("异常模块", test_exceptions()))
    
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
        print("\n模块1 测试全部通过!")
    else:
        print("\n模块1 存在测试失败，请检查!")


if __name__ == "__main__":
    main()
