from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from web.config.database import Base
from datetime import datetime

class ScanRecord(Base):
    __tablename__ = 'scan_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    ports = Column(String(255), nullable=False)
    mode = Column(String(50), default='full')
    status = Column(String(20), default='running')
    results = Column(Text)
    stats = Column(Text)
    created_at = Column(DateTime, default=datetime.now)
    completed_at = Column(DateTime)
    scan_duration = Column(Integer)

    def to_dict(self):
        return {
            'id': self.id,
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
