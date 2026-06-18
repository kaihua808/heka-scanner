#!/usr/bin/env python
"""创建数据库索引以优化查询性能"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.database import DATABASE_URL
from sqlalchemy import create_engine

def create_indexes():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        # 为 scan_records 表创建索引
        try:
            conn.execute("ALTER TABLE scan_records ADD INDEX idx_target (target)")
            print("✓ 创建 idx_target 索引")
        except Exception as e:
            print(f"~ idx_target 索引已存在")
        
        try:
            conn.execute("ALTER TABLE scan_records ADD INDEX idx_status (status)")
            print("✓ 创建 idx_status 索引")
        except Exception as e:
            print(f"~ idx_status 索引已存在")
        
        try:
            conn.execute("ALTER TABLE scan_records ADD INDEX idx_created_at (created_at)")
            print("✓ 创建 idx_created_at 索引")
        except Exception as e:
            print(f"~ idx_created_at 索引已存在")
        
        # 为 scan_results 表创建索引
        try:
            conn.execute("ALTER TABLE scan_results ADD INDEX idx_scan_id (scan_id)")
            print("✓ 创建 idx_scan_id 索引")
        except Exception as e:
            print(f"~ idx_scan_id 索引已存在")
        
        try:
            conn.execute("ALTER TABLE scan_results ADD INDEX idx_ip_port (ip, port)")
            print("✓ 创建 idx_ip_port 索引")
        except Exception as e:
            print(f"~ idx_ip_port 索引已存在")
        
        conn.commit()
        print("\n✅ 索引创建完成！")

if __name__ == '__main__':
    create_indexes()