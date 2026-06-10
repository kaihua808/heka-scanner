from typing import List, Union
from core.exceptions import InvalidPortError


class PortParser:
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }

    WELL_KNOWN_PORTS = list(range(1, 1025))
    REGISTERED_PORTS = list(range(1025, 49152))
    DYNAMIC_PORTS = list(range(49153, 65536))

    def __init__(self):
        pass

    def parse(self, port_input: str) -> List[int]:
        port_input = port_input.strip().lower()

        if not port_input:
            raise InvalidPortError(port_input, "端口输入不能为空")

        if port_input == "all":
            return list(range(1, 65536))

        if port_input == "common":
            return self.WELL_KNOWN_PORTS.copy()

        if port_input == "top20":
            return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017]

        if port_input.startswith("range:"):
            range_part = port_input[6:]
            return self._parse_range(range_part)

        if "," in port_input:
            return self._parse_list(port_input)

        if "-" in port_input and not port_input.startswith("range:"):
            return self._parse_range(port_input)

        try:
            port = int(port_input)
            self._validate_port(port)
            return [port]
        except ValueError:
            raise InvalidPortError(port_input, f"无效的端口格式: {port_input}")

    def _parse_range(self, range_str: str) -> List[int]:
        range_str = range_str.strip()

        if "/" in range_str:
            step_str = range_str.split("/")[1]
            try:
                step = int(step_str)
                range_part = range_str.split("/")[0]
            except ValueError:
                raise InvalidPortError(range_str, f"无效的步长格式: {step_str}")
        else:
            range_part = range_str
            step = 1

        if "-" not in range_part:
            try:
                single_port = int(range_part)
                self._validate_port(single_port)
                return [single_port]
            except ValueError:
                raise InvalidPortError(range_str, f"无效的端口: {range_part}")

        try:
            start_str, end_str = range_part.split("-", 1)
            start = int(start_str.strip())
            end = int(end_str.strip())

            self._validate_port(start)
            self._validate_port(end)

            if start > end:
                raise InvalidPortError(range_str, f"起始端口({start})不能大于结束端口({end})")

            ports = list(range(start, end + 1, step))

            if len(ports) > 65536:
                raise InvalidPortError(range_str, f"端口数量({len(ports)})过多，最多65536个")

            return ports

        except ValueError as e:
            raise InvalidPortError(range_str, f"无效的端口范围格式: {e}")

    def _parse_list(self, list_str: str) -> List[int]:
        ports = []
        seen = set()

        for item in list_str.split(","):
            item = item.strip()
            if not item:
                continue

            if "-" in item:
                try:
                    start_str, end_str = item.split("-", 1)
                    start = int(start_str.strip())
                    end = int(end_str.strip())
                    self._validate_port(start)
                    self._validate_port(end)

                    if start > end:
                        raise InvalidPortError(list_str, f"起始端口({start})不能大于结束端口({end})")

                    for port in range(start, end + 1):
                        if port not in seen:
                            ports.append(port)
                            seen.add(port)

                except ValueError as e:
                    raise InvalidPortError(list_str, f"无效的端口范围: {item}, 错误: {e}")
            else:
                try:
                    port = int(item)
                    self._validate_port(port)
                    if port not in seen:
                        ports.append(port)
                        seen.add(port)
                except ValueError:
                    raise InvalidPortError(list_str, f"无效的端口: {item}")

        return sorted(ports)

    def _validate_port(self, port: int) -> None:
        if not isinstance(port, int):
            raise InvalidPortError(str(port), f"端口必须是整数: {port}")

        if port < 1 or port > 65535:
            raise InvalidPortError(str(port), f"端口必须在1-65535范围内: {port}")

    def is_valid(self, port_input: str) -> bool:
        try:
            self.parse(port_input)
            return True
        except InvalidPortError:
            return False

    def get_port_count(self, port_input: str) -> int:
        try:
            return len(self.parse(port_input))
        except InvalidPortError:
            return 0

    def suggest_port_range(self, service: str) -> str:
        service_lower = service.lower()

        service_map = {
            "web": "80,443,8080,8443",
            "database": "3306,5432,1433,1521,6379,27017",
            "mail": "25,110,143,465,587,993,995",
            "remote": "22,23,3389,5900",
            "file": "21,445,2049",
        }

        if service_lower in service_map:
            return service_map[service_lower]

        return ""

    @staticmethod
    def format_port_list(ports: List[int], max_display: int = 20) -> str:
        if len(ports) <= max_display:
            return ", ".join(str(p) for p in ports)
        else:
            shown = ", ".join(str(p) for p in ports[:max_display])
            return f"{shown}, ... (共{len(ports)}个端口)"


def parse_ports(port_input: str) -> List[int]:
    parser = PortParser()
    return parser.parse(port_input)


def is_valid_port_input(port_input: str) -> bool:
    parser = PortParser()
    return parser.is_valid(port_input)
