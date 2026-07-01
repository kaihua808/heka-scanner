from datetime import datetime

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from services import ScanService


MODE_LABELS = {
    "fast": "快速扫描",
    "full": "全连接扫描",
    "syn": "SYN半开扫描",
    "udp": "UDP扫描",
    "comprehensive": "全面扫描",
}


class ScanWorker(QThread):
    progress_changed = Signal(int, int, int)
    scan_finished = Signal(dict)

    def __init__(self, target: str, ports: str, mode: str, parent=None):
        super().__init__(parent)
        self.target = target
        self.ports = ports
        self.mode = mode
        self.service = ScanService()

    def run(self):
        def report_progress(completed: int, total: int, open_count: int = 0):
            self.progress_changed.emit(completed, total, open_count)

        result = self.service.scan(
            ip_or_cidr=self.target,
            port_str=self.ports,
            scan_mode=self.mode,
            progress_callback=report_progress,
        )
        result["target"] = self.target
        result["ports"] = self.ports
        result["mode"] = self.mode
        result["completed_at"] = datetime.now().isoformat(timespec="seconds")
        self.scan_finished.emit(result)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Heka Scanner")
        self.resize(1180, 760)
        self.worker = None
        self.scan_history = []
        self.current_result = None

        self._build_ui()
        self._apply_styles()

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Heka Scanner 端口扫描器")
        title.setObjectName("title")
        layout.addWidget(title)

        input_box = QGroupBox("新建扫描")
        input_layout = QGridLayout(input_box)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("例如: 127.0.0.1 或 192.168.1.0/24")
        self.target_input.setText("127.0.0.1")

        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("例如: 80,443,1-1000 或 common")
        self.ports_input.setText("1-1000")

        self.mode_combo = QComboBox()
        for key, label in MODE_LABELS.items():
            self.mode_combo.addItem(label, key)
        self.mode_combo.setCurrentIndex(1)

        self.scan_button = QPushButton("开始扫描")
        self.scan_button.clicked.connect(self.start_scan)

        self.clear_button = QPushButton("清空结果")
        self.clear_button.clicked.connect(self.clear_results)

        input_layout.addWidget(QLabel("目标 IP / CIDR"), 0, 0)
        input_layout.addWidget(self.target_input, 0, 1)
        input_layout.addWidget(QLabel("端口范围"), 0, 2)
        input_layout.addWidget(self.ports_input, 0, 3)
        input_layout.addWidget(QLabel("扫描模式"), 1, 0)
        input_layout.addWidget(self.mode_combo, 1, 1)
        input_layout.addWidget(self.scan_button, 1, 2)
        input_layout.addWidget(self.clear_button, 1, 3)
        input_layout.setColumnStretch(1, 2)
        input_layout.setColumnStretch(3, 2)
        layout.addWidget(input_box)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("准备就绪")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.summary_label = QLabel("总数: 0 | 开放: 0 | 关闭: 0 | 过滤: 0 | 耗时: 0.00s")
        status_layout.addWidget(self.status_label, 2)
        status_layout.addWidget(self.progress_bar, 3)
        status_layout.addWidget(self.summary_label, 4)
        layout.addLayout(status_layout)

        content_layout = QHBoxLayout()

        left_layout = QVBoxLayout()
        results_box = QGroupBox("扫描结果")
        results_layout = QVBoxLayout(results_box)
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(["IP", "端口", "状态", "服务", "风险", "响应时间(ms)"])
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)
        left_layout.addWidget(results_box, 4)

        log_box = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_box)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        left_layout.addWidget(log_box, 1)

        history_box = QGroupBox("本次运行历史")
        history_layout = QVBoxLayout(history_box)
        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self.show_history_item)
        history_layout.addWidget(self.history_list)

        content_layout.addLayout(left_layout, 4)
        content_layout.addWidget(history_box, 1)
        layout.addLayout(content_layout, 1)

        self.setCentralWidget(root)

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow { background: #f4f6f8; }
            QLabel#title {
                color: #182433;
                font-size: 24px;
                font-weight: 700;
            }
            QGroupBox {
                border: 1px solid #d7dde5;
                border-radius: 6px;
                margin-top: 12px;
                padding: 12px;
                background: #ffffff;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QLineEdit, QComboBox {
                min-height: 30px;
                border: 1px solid #c9d2dc;
                border-radius: 4px;
                padding: 4px 8px;
                background: #ffffff;
            }
            QPushButton {
                min-height: 30px;
                border: 1px solid #2c6bb2;
                border-radius: 4px;
                padding: 4px 12px;
                background: #2f75c8;
                color: #ffffff;
                font-weight: 600;
            }
            QPushButton:disabled {
                background: #97a6b8;
                border-color: #97a6b8;
            }
            QTableWidget {
                border: 1px solid #d7dde5;
                gridline-color: #e8edf3;
                background: #ffffff;
            }
        """)

    def normalize_target(self, target: str) -> str:
        return "127.0.0.1" if target.strip() == "127001" else target.strip()

    def start_scan(self):
        target = self.normalize_target(self.target_input.text())
        ports = self.ports_input.text().strip() or "1-1000"
        mode = self.mode_combo.currentData()

        if not target:
            QMessageBox.warning(self, "输入错误", "目标 IP / CIDR 不能为空")
            return

        self.target_input.setText(target)
        self.scan_button.setEnabled(False)
        self.scan_button.setText("扫描中...")
        self.progress_bar.setValue(0)
        self.status_label.setText("正在扫描")
        self.log_output.appendPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] 开始扫描 {target} 端口 {ports}")

        self.worker = ScanWorker(target, ports, mode, self)
        self.worker.progress_changed.connect(self.update_progress)
        self.worker.scan_finished.connect(self.finish_scan)
        self.worker.start()

    def update_progress(self, completed: int, total: int, open_count: int):
        percent = int((completed / total) * 100) if total else 0
        self.progress_bar.setValue(percent)
        self.status_label.setText(f"扫描中 {completed}/{total} | 开放 {open_count}")

    def finish_scan(self, result: dict):
        self.current_result = result
        self.scan_history.insert(0, result)
        self.render_result(result)
        self.add_history_item(result)

        self.scan_button.setEnabled(True)
        self.scan_button.setText("开始扫描")
        self.progress_bar.setValue(100 if result.get("success") else 0)

        if result.get("success"):
            self.status_label.setText("扫描完成")
            self.log_output.appendPlainText(
                f"[{datetime.now().strftime('%H:%M:%S')}] 扫描完成，结果 {len(result.get('results', []))} 条"
            )
        else:
            self.status_label.setText("扫描失败")
            reason = result.get("error", "未知错误")
            if result.get("violation"):
                reason = result["violation"].get("reason", reason)
            self.log_output.appendPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] 扫描失败: {reason}")
            QMessageBox.warning(self, "扫描失败", reason)

    def render_result(self, result: dict):
        rows = result.get("results", [])
        self.results_table.setRowCount(len(rows))

        for row_index, row in enumerate(rows):
            values = [
                row.get("ip", ""),
                str(row.get("port", "")),
                self.status_text(row.get("status", "")),
                row.get("service", "") or "Unknown",
                self.risk_text(row.get("risk_level", "")),
                f"{row.get('response_time', 0):.2f}",
            ]
            for col_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignCenter)
                if col_index == 2:
                    item.setForeground(self.status_color(row.get("status", "")))
                if col_index == 4:
                    item.setForeground(self.risk_color(row.get("risk_level", "")))
                self.results_table.setItem(row_index, col_index, item)

        stats = result.get("stats", {})
        self.summary_label.setText(
            f"总数: {stats.get('total', 0)} | 开放: {stats.get('open', 0)} | "
            f"关闭: {stats.get('closed', 0)} | 过滤: {stats.get('filtered', 0)} | "
            f"耗时: {stats.get('duration', result.get('duration', 0)):.2f}s"
        )

    def add_history_item(self, result: dict):
        stats = result.get("stats", {})
        label = (
            f"{result.get('completed_at', '')}  {result.get('target', '')}  "
            f"{result.get('ports', '')}  {MODE_LABELS.get(result.get('mode'), result.get('mode'))}  "
            f"开放 {stats.get('open', 0)}"
        )
        item = QListWidgetItem(label)
        item.setData(Qt.UserRole, result)
        self.history_list.insertItem(0, item)

    def show_history_item(self, item: QListWidgetItem):
        result = item.data(Qt.UserRole)
        if result:
            self.current_result = result
            self.render_result(result)

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.current_result = None
        self.progress_bar.setValue(0)
        self.status_label.setText("准备就绪")
        self.summary_label.setText("总数: 0 | 开放: 0 | 关闭: 0 | 过滤: 0 | 耗时: 0.00s")

    @staticmethod
    def status_text(status: str) -> str:
        return {"open": "开放", "closed": "关闭", "filtered": "过滤", "unknown": "未知"}.get(status, status)

    @staticmethod
    def risk_text(risk: str) -> str:
        return {"high": "高危", "medium": "中危", "low": "低危"}.get(risk, risk or "低危")

    @staticmethod
    def status_color(status: str) -> QColor:
        colors = {"open": "#198754", "closed": "#6c757d", "filtered": "#b58100", "unknown": "#6c757d"}
        return QColor(colors.get(status, "#333333"))

    @staticmethod
    def risk_color(risk: str) -> QColor:
        colors = {"high": "#dc3545", "medium": "#fd7e14", "low": "#198754"}
        return QColor(colors.get(risk, "#198754"))
