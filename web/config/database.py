import os
import pymysql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

MYSQL_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'root_admin_test',
    'database': 'port_scanner'
}

DATABASE_URL = f"mysql+pymysql://{MYSQL_CONFIG['user']}:{MYSQL_CONFIG['password']}@{MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}/{MYSQL_CONFIG['database']}"

try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    MYSQL_AVAILABLE = True
except Exception as e:
    print(f"MySQL connection failed, will fallback to file storage: {e}")
    MYSQL_AVAILABLE = False
    engine = None
    SessionLocal = None
    Base = None

def get_db():
    if not MYSQL_AVAILABLE:
        return None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_database():
    if not MYSQL_AVAILABLE:
        return False
    try:
        engine.connect()
        return True
    except Exception as e:
        print(f"Failed to connect to MySQL: {e}")
        return False
