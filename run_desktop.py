#!/usr/bin/env python3
import sys

from PySide6.QtWidgets import QApplication

from desktop import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
