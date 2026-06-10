import pymysql
from web.config.database import MYSQL_CONFIG, Base, engine

def create_database():
    try:
        conn = pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password']
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']}")
        conn.close()
        print(f"Database '{MYSQL_CONFIG['database']}' created successfully")
    except Exception as e:
        print(f"Error creating database: {e}")

def create_tables():
    if engine is None:
        print("MySQL not available, skipping table creation")
        return
    try:
        Base.metadata.create_all(bind=engine)
        print("All tables created successfully")
    except Exception as e:
        print(f"Error creating tables: {e}")

if __name__ == "__main__":
    create_database()
    create_tables()
