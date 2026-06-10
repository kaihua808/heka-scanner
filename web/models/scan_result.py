from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text
from web.config.database import Base

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    record_id = Column(Integer, ForeignKey('scan_records.id'))
    ip_address = Column(String(50))
    port = Column(Integer)
    status = Column(String(20))
    service = Column(String(100))
    response_time = Column(Float)
    risk_level = Column(String(20))
    version = Column(String(100))

    def to_dict(self):
        return {
            'id': self.id,
            'record_id': self.record_id,
            'ip_address': self.ip_address,
            'port': self.port,
            'status': self.status,
            'service': self.service,
            'response_time': self.response_time,
            'risk_level': self.risk_level,
            'version': self.version
        }
