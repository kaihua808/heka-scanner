from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import relationship
from web.config.database import Base
from datetime import datetime

class ScanRecord(Base):
    __tablename__ = 'scan_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))  # 添加用户ID字段
    target = Column(String(255), nullable=False)
    ports = Column(String(255), nullable=False)
    mode = Column(String(50), default='full')
    status = Column(String(20), default='running')
    results = Column(LONGTEXT)  # 使用 LONGTEXT 支持更大的数据
    stats = Column(LONGTEXT)
    created_at = Column(DateTime, default=datetime.now)
    completed_at = Column(DateTime)
    scan_duration = Column(Integer)
    
    # 关联用户
    user = relationship('User', backref='scan_records')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target': self.target,
            'ports': self.ports,
            'mode': self.mode,
            'status': self.status,
            'results': self.results,
            'stats': self.stats,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'scan_duration': self.scan_duration
        }