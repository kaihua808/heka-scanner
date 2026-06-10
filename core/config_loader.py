import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path


class ConfigLoader:
    _instance = None
    _config = None

    def __new__(cls, config_path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_path: Optional[str] = None):
        if self._config is None:
            self.config_path = config_path or self._get_default_config_path()
            self._config = self._load_config()

    def _get_default_config_path(self) -> str:
        current_dir = Path(__file__).parent.parent
        return str(current_dir / "config" / "settings.yaml")

    def _load_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        if config is None:
            raise ValueError(f"配置文件为空或格式错误: {self.config_path}")
        
        return config

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value

    def get_section(self, section: str) -> Dict[str, Any]:
        return self._config.get(section, {})

    @property
    def scanner(self) -> Dict[str, Any]:
        return self.get_section('scanner')

    @property
    def scan(self) -> Dict[str, Any]:
        return self.get_section('scan')

    @property
    def bandwidth(self) -> Dict[str, Any]:
        return self.get_section('bandwidth')

    @property
    def compliance(self) -> Dict[str, Any]:
        return self.get_section('compliance')

    @property
    def services(self) -> Dict[str, Any]:
        return self.get_section('services')

    @property
    def risk(self) -> Dict[str, Any]:
        return self.get_section('risk')

    @property
    def output(self) -> Dict[str, Any]:
        return self.get_section('output')

    @property
    def audit(self) -> Dict[str, Any]:
        return self.get_section('audit')

    @property
    def logging(self) -> Dict[str, Any]:
        return self.get_section('logging')

    def reload(self, config_path: Optional[str] = None) -> None:
        if config_path:
            self.config_path = config_path
        self._config = self._load_config()

    def validate(self) -> bool:
        required_sections = ['scanner', 'scan', 'compliance', 'services', 'risk', 'output']
        
        for section in required_sections:
            if section not in self._config:
                raise ValueError(f"配置缺少必要部分: {section}")
        
        return True

    def display(self) -> str:
        lines = ["=" * 50, "当前配置信息", "=" * 50]
        
        sections = [
            ('扫描器信息', self.scanner),
            ('扫描配置', self.scan),
            ('带宽控制', self.bandwidth),
            ('合规配置', self.compliance),
            ('风险配置', self.risk),
            ('输出配置', self.output),
        ]
        
        for title, config in sections:
            lines.append(f"\n【{title}】")
            for key, value in config.items():
                lines.append(f"  {key}: {value}")
        
        lines.append("\n" + "=" * 50)
        return "\n".join(lines)
