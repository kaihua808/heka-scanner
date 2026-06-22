import json
from datetime import datetime
from web.config.database import MYSQL_AVAILABLE, get_db, init_database
from web.models.scan_record import ScanRecord
from web.models.scan_result import ScanResult
from web.models.user import User

class DatabaseService:
    def __init__(self):
        self.mysql_available = MYSQL_AVAILABLE
        if self.mysql_available:
            init_database()
    
    # ============ 用户管理功能 ============
    
    def create_user(self, username, password, email=None):
        if not self.mysql_available:
            return None
        
        db = next(get_db())
        
        # 检查用户名是否已存在
        if db.query(User).filter_by(username=username).first():
            return None
        
        # 检查邮箱是否已存在
        if email and db.query(User).filter_by(email=email).first():
            return None
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    
    def get_user_by_username(self, username):
        if not self.mysql_available:
            return None
        
        db = next(get_db())
        return db.query(User).filter_by(username=username).first()
    
    def get_user_by_id(self, user_id):
        if not self.mysql_available:
            return None
        
        db = next(get_db())
        return db.query(User).filter_by(id=user_id).first()
    
    def update_user_last_login(self, user_id):
        if not self.mysql_available:
            return False
        
        db = next(get_db())
        user = db.query(User).filter_by(id=user_id).first()
        if user:
            user.last_login = datetime.now()
            db.commit()
            return True
        return False
    
    def get_all_users(self):
        if not self.mysql_available:
            return []
        
        db = next(get_db())
        return db.query(User).all()
    
    # ============ 扫描记录功能 ============
    
    def save_scan_record(self, target, ports, mode='full', user_id=None):
        if not self.mysql_available:
            return None
        
        db = next(get_db())
        record = ScanRecord(
            user_id=user_id,
            target=target,
            ports=ports,
            mode=mode,
            status='running'
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record.id
    
    def update_scan_status(self, record_id, status, results=None, stats=None, duration=None):
        if not self.mysql_available:
            return False
        
        db = next(get_db())
        record = db.query(ScanRecord).filter_by(id=record_id).first()
        if record:
            record.status = status
            if results:
                record.results = json.dumps(results)
            if stats:
                record.stats = json.dumps(stats)
            if duration:
                record.scan_duration = duration
            record.completed_at = datetime.now()
            db.commit()
            return True
        return False
    
    def get_scan_record(self, record_id):
        if not self.mysql_available:
            return None
        
        db = next(get_db())
        record = db.query(ScanRecord).filter_by(id=record_id).first()
        if record:
            data = record.to_dict()
            if data['results']:
                data['results'] = json.loads(data['results'])
            if data['stats']:
                data['stats'] = json.loads(data['stats'])
            return data
        return None
    
    def get_all_records(self, limit=20, offset=0, user_id=None):
        if not self.mysql_available:
            return []
        
        db = next(get_db())
        query = db.query(ScanRecord).order_by(ScanRecord.created_at.desc())
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        # 使用 joinedload 预加载用户数据，避免懒加载问题
        from sqlalchemy.orm import joinedload
        records = query.options(joinedload(ScanRecord.user)).limit(limit).offset(offset).all()
        result = []
        for record in records:
            data = record.to_dict()
            
            # 获取用户名
            if record.user:
                data['username'] = record.user.username
            else:
                data['username'] = '未知用户'
            
            if data['results']:
                try:
                    data['results'] = json.loads(data['results'])
                except:
                    data['results'] = []
            if data['stats']:
                try:
                    data['stats'] = json.loads(data['stats'])
                except:
                    data['stats'] = {}
            result.append(data)
        return result
    
    def delete_scan_record(self, record_id):
        if not self.mysql_available:
            return False
        
        db = next(get_db())
        record = db.query(ScanRecord).filter_by(id=record_id).first()
        if record:
            db.delete(record)
            db.commit()
            return True
        return False
    
    def save_scan_results(self, record_id, results):
        if not self.mysql_available:
            return False
        
        db = next(get_db())
        for result in results:
            scan_result = ScanResult(
                record_id=record_id,
                ip_address=result.get('ip_address', ''),
                port=result.get('port', 0),
                status=result.get('status', ''),
                service=result.get('service', ''),
                response_time=result.get('response_time', 0.0),
                risk_level=result.get('risk_level', ''),
                version=result.get('version', '')
            )
            db.add(scan_result)
        db.commit()
        return True
    
    def get_total_count(self, user_id=None):
        """获取历史记录总数"""
        if not self.mysql_available:
            return 0
        
        db = next(get_db())
        query = db.query(ScanRecord)
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        return query.count()
    
    def clear_all_records(self):
        if not self.mysql_available:
            return False
        
        db = next(get_db())
        db.query(ScanResult).delete()
        db.query(ScanRecord).delete()
        db.commit()
        return True

db_service = DatabaseService()