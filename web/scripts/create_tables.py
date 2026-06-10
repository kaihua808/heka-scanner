import pymysql

MYSQL_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '123456',
    'database': 'port_scanner'
}

def create_tables():
    try:
        conn = pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password'],
            database=MYSQL_CONFIG['database']
        )
        cursor = conn.cursor()
        
        # 创建 scan_records 表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                target VARCHAR(255) NOT NULL,
                ports VARCHAR(255) NOT NULL,
                mode VARCHAR(50) DEFAULT 'full',
                status VARCHAR(20) DEFAULT 'running',
                results TEXT,
                stats TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                scan_duration INT
            )
        ''')
        
        # 创建 scan_results 表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                record_id INT,
                ip_address VARCHAR(50),
                port INT,
                status VARCHAR(20),
                service VARCHAR(100),
                response_time FLOAT,
                risk_level VARCHAR(20),
                version VARCHAR(100)
            )
        ''')
        
        conn.commit()
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print("Tables created successfully:")
        for table in tables:
            print(f"- {table[0]}")
        
        conn.close()
    except Exception as e:
        print(f"Error creating tables: {e}")

if __name__ == "__main__":
    create_tables()
