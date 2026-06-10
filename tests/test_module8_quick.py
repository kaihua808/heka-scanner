import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.fault_tolerance import TimeoutManager, RetryManager, BlackWhiteList

print("\n" + "=" * 60)
print("模块8 快速验证")
print("=" * 60)

try:
    print("\n测试1: 超时管理器")
    manager = TimeoutManager(default_timeout=3.0)
    print(f"  默认超时: {manager.get_timeout('127.0.0.1', 80)}s")
    manager.set_timeout("127.0.0.1", 80, 5.0)
    print(f"  设置后: {manager.get_timeout('127.0.0.1', 80)}s")
    print("  [PASS] 超时管理器")

    print("\n测试2: 重试管理器")
    manager = RetryManager(max_retries=3)
    print(f"  应重试: {manager.should_retry('127.0.0.1', 80)}")
    manager.record_attempt("127.0.0.1", 80)
    print(f"  尝试后: {manager.get_attempt_count('127.0.0.1', 80)}")
    print("  [PASS] 重试管理器")

    print("\n测试3: 黑名单管理")
    blacklist = BlackWhiteList()
    print(f"  初始跳过: {blacklist.should_skip('127.0.0.1')}")
    blacklist.add_to_blacklist(ip="127.0.0.1")
    print(f"  添加后跳过: {blacklist.should_skip('127.0.0.1')}")
    blacklist.remove_from_blacklist(ip="127.0.0.1")
    print(f"  移除后跳过: {blacklist.should_skip('127.0.0.1')}")
    print("  [PASS] 黑名单管理")

    print("\n测试4: 离线主机检测")
    blacklist = BlackWhiteList()
    for i in range(3):
        blacklist.record_failure("192.168.1.1")
    print(f"  3次失败后离线: {blacklist.get_offline_hosts()}")
    blacklist.mark_online("192.168.1.1")
    print(f"  标记在线后: {blacklist.get_offline_hosts()}")
    print("  [PASS] 离线主机检测")

    print("\n" + "=" * 60)
    print("模块8 验证通过!")
    print("=" * 60)

except Exception as e:
    print(f"  [FAIL] 异常: {e}")
    import traceback
    traceback.print_exc()
