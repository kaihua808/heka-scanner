import csv
import json
import os
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from services import ScanService


MODE_LABELS = {
    "fast": "快速扫描",
    "full": "全连接扫描",
    "udp": "UDP扫描",
    "comprehensive": "全面扫描",
}


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def get_progress_delay_ms() -> int:
    try:
        delay = int(os.getenv("HEKA_PROGRESS_DELAY_MS", "0"))
    except ValueError:
        return 0
    return max(0, min(delay, 1000))


class ScanWorker(QThread):
    progress_changed = Signal(int, int, int, str, str)
    result_signal = Signal(dict)
    scan_finished = Signal(dict)

    def __init__(self, target: str, ports: str, mode: str, parent=None):
        super().__init__(parent)
        self.target = target
        self.ports = ports
        self.mode = mode
        self.service = ScanService()
        self.start_time = None
        self.progress_delay_ms = get_progress_delay_ms()

    def run(self):
        def report_progress(completed: int, total: int, open_count: int = 0):
            elapsed_seconds = time.time() - self.start_time if self.start_time else 0
            elapsed = format_duration(elapsed_seconds)

            if completed <= 0:
                eta = "计算中"
            else:
                average_speed = completed / elapsed_seconds if elapsed_seconds > 0 else 0
                remaining = max(total - completed, 0)
                eta = format_duration(remaining / average_speed) if average_speed > 0 else "计算中"

            self.progress_changed.emit(completed, total, open_count, elapsed, eta)
            if self.progress_delay_ms and completed > 0:
                time.sleep(self.progress_delay_ms / 1000)

        def report_result(row: dict):
            self.result_signal.emit(row)

        self.start_time = time.time()
        result = self.service.scan(
            ip_or_cidr=self.target,
            port_str=self.ports,
            scan_mode=self.mode,
            progress_callback=report_progress,
            result_callback=report_result,
        )
        result["target"] = self.target
        result["ports"] = self.ports
        result["mode"] = self.mode
        result["completed_at"] = datetime.now().isoformat(timespec="seconds")
        self.scan_finished.emit(result)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._force_light_theme()
        self.setWindowTitle("Heka Scanner")
        self.resize(1180, 760)
        self.worker = None
        self.history_path = Path("data/scan_history.json")
        self.scan_history = self.load_scan_history()
        self.current_result = None
        self.selected_history_result = None

        self._build_ui()
        self._apply_styles()
        self.refresh_history_table()

    def _force_light_theme(self):
        app = QApplication.instance()
        if not app:
            return

        app.setStyle("Fusion")
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#f4f6f8"))
        palette.setColor(QPalette.WindowText, QColor("#1f2933"))
        palette.setColor(QPalette.Base, QColor("#ffffff"))
        palette.setColor(QPalette.AlternateBase, QColor("#f7f9fc"))
        palette.setColor(QPalette.Text, QColor("#1f2933"))
        palette.setColor(QPalette.Button, QColor("#ffffff"))
        palette.setColor(QPalette.ButtonText, QColor("#1f2933"))
        palette.setColor(QPalette.ToolTipBase, QColor("#ffffff"))
        palette.setColor(QPalette.ToolTipText, QColor("#1f2933"))
        palette.setColor(QPalette.Highlight, QColor("#2f75c8"))
        palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
        app.setPalette(palette)

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Heka Scanner 端口扫描器")
        title.setObjectName("title")
        layout.addWidget(title)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_scan_tab(), "新建扫描")
        self.tabs.addTab(self._build_history_tab(), "扫描历史")
        layout.addWidget(self.tabs, 1)

        self.setCentralWidget(root)

    def _build_scan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(14)

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
        self.summary_label = QLabel("总数: 0 | 开放: 0 | 关闭: 0 | 过滤: 0 | 开放或过滤: 0 | 未知: 0 | 耗时: 0.00s")
        status_layout.addWidget(self.status_label, 2)
        status_layout.addWidget(self.progress_bar, 3)
        status_layout.addWidget(self.summary_label, 4)
        layout.addLayout(status_layout)

        results_box = QGroupBox("扫描结果")
        results_layout = QVBoxLayout(results_box)
        self.results_table = QTableWidget(0, 7)
        self.results_table.setHorizontalHeaderLabels(["IP", "端口", "协议", "状态", "服务", "风险", "响应时间(ms)"])
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)
        layout.addWidget(results_box, 5)

        log_box = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_box)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        layout.addWidget(log_box, 2)

        return tab

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(14)

        history_box = QGroupBox("历史扫描记录")
        history_layout = QVBoxLayout(history_box)

        history_actions = QHBoxLayout()
        history_actions.addWidget(QLabel("导出格式"))
        self.export_format_combo = QComboBox()
        self.export_format_combo.addItem("CSV 文件", "csv")
        self.export_format_combo.addItem("JSON 文件", "json")
        history_actions.addWidget(self.export_format_combo)

        self.export_button = QPushButton("导出")
        self.export_button.clicked.connect(self.export_selected_history)
        self.clear_history_button = QPushButton("清空历史记录")
        self.clear_history_button.clicked.connect(self.confirm_clear_history)
        history_actions.addStretch(1)
        history_actions.addWidget(self.export_button)
        history_actions.addWidget(self.clear_history_button)
        history_layout.addLayout(history_actions)

        self.history_table = QTableWidget(0, 5)
        self.history_table.setObjectName("historyTable")
        self.history_table.setHorizontalHeaderLabels(["扫描时间", "目标 IP / CIDR", "端口范围", "扫描模式", "结果数量"])
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.cellClicked.connect(self.show_history_row)
        history_layout.addWidget(self.history_table)
        layout.addWidget(history_box, 2)

        details_box = QGroupBox("历史扫描详情")
        details_layout = QVBoxLayout(details_box)
        self.history_detail_table = QTableWidget(0, 7)
        self.history_detail_table.setHorizontalHeaderLabels(["IP", "端口", "协议", "状态", "服务", "风险", "响应时间(ms)"])
        self.history_detail_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_detail_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_detail_table.setAlternatingRowColors(True)
        self.history_detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        details_layout.addWidget(self.history_detail_table)
        layout.addWidget(details_box, 3)

        return tab

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #f4f6f8;
                color: #1f2933;
            }
            QLabel {
                color: #1f2933;
                background: transparent;
            }
            QLabel#title {
                color: #182433;
                font-size: 24px;
                font-weight: 700;
            }
            QTabWidget::pane {
                border: 1px solid #d7dde5;
                border-radius: 6px;
                background: #ffffff;
                top: -1px;
            }
            QTabBar::tab {
                min-width: 120px;
                min-height: 34px;
                padding: 6px 18px;
                border: 1px solid #c9d2dc;
                border-bottom: 0;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                background: #eef3f8;
                color: #1f2933;
                font-weight: 700;
            }
            QTabBar::tab:selected {
                background: #2f75c8;
                color: #ffffff;
                border-color: #2c6bb2;
            }
            QTabBar::tab:hover:!selected {
                background: #dcecff;
            }
            QGroupBox {
                border: 1px solid #d7dde5;
                border-radius: 6px;
                margin-top: 12px;
                padding: 12px;
                background: #ffffff;
                color: #1f2933;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
                color: #1f2933;
                background: #ffffff;
            }
            QLineEdit {
                min-height: 30px;
                border: 1px solid #c9d2dc;
                border-radius: 4px;
                padding: 4px 8px;
                background: #ffffff;
                color: #182433;
                selection-background-color: #2f75c8;
                selection-color: #ffffff;
            }
            QLineEdit::placeholder {
                color: #6b7785;
            }
            QComboBox {
                min-height: 30px;
                border: 1px solid #c9d2dc;
                border-radius: 4px;
                padding: 4px 34px 4px 8px;
                background: #ffffff;
                color: #182433;
                selection-background-color: #2f75c8;
                selection-color: #ffffff;
            }
            QComboBox:hover {
                border-color: #7aa7d9;
                background: #fbfdff;
            }
            QComboBox:focus, QComboBox:on {
                border: 1px solid #2f75c8;
                background: #ffffff;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 28px;
                border-left: 1px solid #d7dde5;
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
                background: #f7f9fc;
            }
            QComboBox::drop-down:hover {
                background: #edf5ff;
            }
            QComboBox QAbstractItemView {
                border: 1px solid #c9d2dc;
                outline: 0;
                background: #ffffff;
                color: #182433;
                selection-background-color: #dcecff;
                selection-color: #182433;
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
            QPushButton:hover {
                background: #2867b1;
            }
            QPushButton:pressed {
                background: #225894;
            }
            QPushButton:disabled {
                background: #d6dde6;
                border-color: #c7d0da;
                color: #64748b;
            }
            QProgressBar {
                min-height: 18px;
                border: 1px solid #c9d2dc;
                border-radius: 4px;
                background: #ffffff;
                color: #1f2933;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #2f75c8;
                border-radius: 3px;
            }
            QTableWidget {
                border: 1px solid #d7dde5;
                gridline-color: #e8edf3;
                background: #ffffff;
                alternate-background-color: #f7f9fc;
                color: #1f2933;
                selection-background-color: #dcecff;
                selection-color: #182433;
            }
            QTableWidget::item {
                padding: 4px;
                color: #1f2933;
            }
            QHeaderView::section {
                background: #e9eef5;
                color: #182433;
                border: 0;
                border-right: 1px solid #d7dde5;
                border-bottom: 1px solid #c9d2dc;
                padding: 6px;
                font-weight: 700;
            }
            QPlainTextEdit, QTextEdit {
                border: 1px solid #d7dde5;
                border-radius: 4px;
                background: #fbfcfe;
                color: #1f2933;
                selection-background-color: #dcecff;
                selection-color: #182433;
            }
            QTableWidget#historyTable {
                border: 1px solid #d7dde5;
                border-radius: 4px;
                background: #fbfcfe;
                color: #1f2933;
                selection-background-color: #dcecff;
                selection-color: #182433;
            }
            QMessageBox {
                background: #ffffff;
                color: #1f2933;
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
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("扫描中 0/0 | 0% | 已耗时 00:00 | ETA 计算中")
        self.log_output.appendPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] 开始扫描 {target} 端口 {ports}")

        self.worker = ScanWorker(target, ports, mode, self)
        self.worker.progress_changed.connect(self.update_progress)
        self.worker.result_signal.connect(self.append_result_row)
        self.worker.scan_finished.connect(self.finish_scan)
        self.worker.start()

    def update_progress(self, completed: int, total: int, open_count: int, elapsed: str, eta: str):
        percent = int((completed / total) * 100) if total else 0
        self.progress_bar.setValue(percent)
        self.status_label.setText(
            f"扫描中 {completed}/{total} | {percent}% | 已耗时 {elapsed} | ETA {eta} | 开放 {open_count}"
        )

    def finish_scan(self, result: dict):
        self.current_result = result
        self.scan_history.insert(0, result)
        self.save_scan_history()
        self.update_summary(result)
        self.refresh_history_table()

        self.scan_button.setEnabled(True)
        self.scan_button.setText("开始扫描")
        self.progress_bar.setValue(100 if result.get("success") else 0)

        if result.get("success"):
            stats = result.get("stats", {})
            total = stats.get("total", len(result.get("results", [])))
            self.status_label.setText(
                f"扫描完成 {total}/{total} | 100% | 已耗时 {format_duration(result.get('duration', 0))} | ETA 已完成"
            )
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
        self.render_results_table(self.results_table, result)
        self.update_summary(result)

    def update_summary(self, result: dict):
        stats = result.get("stats", {})
        self.summary_label.setText(
            f"总数: {stats.get('total', 0)} | 开放: {stats.get('open', 0)} | "
            f"关闭: {stats.get('closed', 0)} | 过滤: {stats.get('filtered', 0)} | "
            f"开放或过滤: {stats.get('open_or_filtered', 0)} | 未知: {stats.get('unknown', 0)} | "
            f"耗时: {stats.get('duration', result.get('duration', 0)):.2f}s"
        )

    def append_result_row(self, row: dict):
        row_index = self.results_table.rowCount()
        self.results_table.insertRow(row_index)
        self.set_result_row(self.results_table, row_index, row)
        self.results_table.scrollToBottom()

    def render_results_table(self, table: QTableWidget, result: dict):
        rows = result.get("results", [])
        table.setRowCount(len(rows))

        for row_index, row in enumerate(rows):
            self.set_result_row(table, row_index, row)

        table.resizeRowsToContents()

    def set_result_row(self, table: QTableWidget, row_index: int, row: dict):
        values = [
            row.get("ip", ""),
            str(row.get("port", "")),
            row.get("protocol", "tcp").upper(),
            self.status_text(row.get("status", "")),
            row.get("service", "") or "Unknown",
            self.risk_text(row.get("risk_level", "")),
            f"{row.get('response_time', 0):.2f}",
        ]
        for col_index, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignCenter)
            if col_index == 3:
                item.setForeground(self.status_color(row.get("status", "")))
            if col_index == 5:
                item.setForeground(self.risk_color(row.get("risk_level", "")))
            table.setItem(row_index, col_index, item)

    def load_scan_history(self) -> list:
        if not self.history_path.exists():
            return []
        try:
            with self.history_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def save_scan_history(self):
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("w", encoding="utf-8") as f:
            json.dump(self.scan_history, f, ensure_ascii=False, indent=2)

    def refresh_history_table(self):
        self.history_table.setRowCount(0)
        for result in self.scan_history:
            self.add_history_item(result)
        if not self.scan_history:
            self.selected_history_result = None
            self.history_detail_table.setRowCount(0)

    def add_history_item(self, result: dict):
        values = [
            result.get("completed_at", ""),
            result.get("target", ""),
            result.get("ports", ""),
            MODE_LABELS.get(result.get("mode"), result.get("mode", "")),
            str(len(result.get("results", []))),
        ]

        self.history_table.insertRow(0)
        for col_index, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignCenter)
            item.setData(Qt.UserRole, result)
            self.history_table.setItem(0, col_index, item)
        self.history_table.resizeRowsToContents()

    def show_history_row(self, row: int, _column: int):
        item = self.history_table.item(row, 0)
        result = item.data(Qt.UserRole) if item else None
        if result:
            self.selected_history_result = result
            self.render_results_table(self.history_detail_table, result)

    def export_selected_history(self):
        if not self.selected_history_result:
            QMessageBox.information(self, "请选择记录", "请先在扫描历史中选择一条记录")
            return

        export_format = self.export_format_combo.currentData()
        extension = "json" if export_format == "json" else "csv"
        file_filter = "JSON 文件 (*.json)" if export_format == "json" else "CSV 文件 (*.csv)"
        default_name = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}"
        file_path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出扫描结果",
            default_name,
            file_filter
        )
        if not file_path:
            return

        try:
            path = self.ensure_export_extension(Path(file_path), extension)
            if export_format == "json":
                self.export_history_to_json(self.selected_history_result, path)
            else:
                self.export_history_to_csv(self.selected_history_result, path)
            QMessageBox.information(self, "导出完成", f"扫描结果已导出到:\n{path}")
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    def export_history_to_csv(self, result: dict, file_path: Path):
        export_data = self.build_export_data(result)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "scan_time",
                    "target",
                    "ports",
                    "mode",
                    "ip",
                    "port",
                    "protocol",
                    "scan_type",
                    "status",
                    "service",
                    "risk_level",
                    "response_time",
                ]
            )
            writer.writeheader()
            for row in export_data["results"]:
                writer.writerow({
                    "scan_time": export_data["scan_time"],
                    "target": export_data["target"],
                    "ports": export_data["ports"],
                    "mode": export_data["mode"],
                    "ip": row.get("ip", ""),
                    "port": row.get("port", ""),
                    "protocol": row.get("protocol", ""),
                    "scan_type": row.get("scan_type", ""),
                    "status": row.get("status", ""),
                    "service": row.get("service", ""),
                    "risk_level": row.get("risk_level", ""),
                    "response_time": row.get("response_time", ""),
                })

    def export_history_to_json(self, result: dict, file_path: Path):
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("w", encoding="utf-8") as f:
            json.dump(self.build_export_data(result), f, ensure_ascii=False, indent=2)

    def build_export_data(self, result: dict) -> dict:
        return {
            "scan_time": result.get("completed_at", ""),
            "target": result.get("target", ""),
            "ports": result.get("ports", ""),
            "mode": MODE_LABELS.get(result.get("mode"), result.get("mode", "")),
            "results": [
                {
                    "ip": row.get("ip", ""),
                    "port": row.get("port", ""),
                    "protocol": row.get("protocol", "tcp"),
                    "scan_type": row.get("scan_type", "tcp_connect"),
                    "status": self.status_text(row.get("status", "")),
                    "service": row.get("service", "") or "Unknown",
                    "risk_level": self.risk_text(row.get("risk_level", "")),
                    "response_time": f"{row.get('response_time', 0):.2f}",
                }
                for row in result.get("results", [])
            ],
        }

    @staticmethod
    def ensure_export_extension(file_path: Path, extension: str) -> Path:
        suffix = f".{extension}"
        return file_path if file_path.suffix.lower() == suffix else file_path.with_suffix(suffix)

    def confirm_clear_history(self):
        if not self.scan_history:
            QMessageBox.information(self, "历史记录为空", "当前没有可清空的历史记录")
            return

        reply = QMessageBox.question(
            self,
            "清空历史记录",
            "确认清空全部历史扫描记录吗？本地历史文件也会被清空。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.clear_history_records()

    def clear_history_records(self):
        self.scan_history = []
        self.selected_history_result = None
        self.save_scan_history()
        self.refresh_history_table()

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.current_result = None
        self.progress_bar.setValue(0)
        self.status_label.setText("准备就绪")
        self.summary_label.setText("总数: 0 | 开放: 0 | 关闭: 0 | 过滤: 0 | 开放或过滤: 0 | 未知: 0 | 耗时: 0.00s")

    @staticmethod
    def status_text(status: str) -> str:
        return {
            "open": "开放",
            "closed": "关闭",
            "filtered": "过滤",
            "open_or_filtered": "开放或过滤",
            "unknown": "未知",
        }.get(status, status)

    @staticmethod
    def risk_text(risk: str) -> str:
        return {"high": "高危", "medium": "中危", "low": "低危"}.get(risk, risk or "低危")

    @staticmethod
    def status_color(status: str) -> QColor:
        colors = {
            "open": "#198754",
            "closed": "#6c757d",
            "filtered": "#b58100",
            "open_or_filtered": "#b58100",
            "unknown": "#6c757d",
        }
        return QColor(colors.get(status, "#333333"))

    @staticmethod
    def risk_color(risk: str) -> QColor:
        colors = {"high": "#dc3545", "medium": "#fd7e14", "low": "#198754"}
        return QColor(colors.get(risk, "#198754"))
