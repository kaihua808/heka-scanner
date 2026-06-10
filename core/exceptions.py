class ScannerException(Exception):
    pass


class ComplianceViolationError(ScannerException):
    def __init__(self, ip: str, reason: str):
        self.ip = ip
        self.reason = reason
        super().__init__(f"合规违规: {ip} - {reason}")


class InvalidIPError(ScannerException):
    def __init__(self, ip: str, reason: str):
        self.ip = ip
        self.reason = reason
        super().__init__(f"无效IP: {ip} - {reason}")


class InvalidPortError(ScannerException):
    def __init__(self, port: str, reason: str):
        self.port = port
        self.reason = reason
        super().__init__(f"无效端口: {port} - {reason}")


class ScanTimeoutError(ScannerException):
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        super().__init__(f"扫描超时: {ip}:{port}")


class ThreadDeadlockError(ScannerException):
    def __init__(self, thread_id: int, reason: str):
        self.thread_id = thread_id
        self.reason = reason
        super().__init__(f"线程死锁: Thread-{thread_id} - {reason}")


class ConfigError(ScannerException):
    def __init__(self, message: str):
        super().__init__(f"配置错误: {message}")


class OutputError(ScannerException):
    def __init__(self, message: str):
        super().__init__(f"输出错误: {message}")
