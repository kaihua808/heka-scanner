@echo off
echo ========================================
echo    端口扫描器 Web 管理界面
echo ========================================
echo.
echo 启动Web服务...
echo 访问地址: http://localhost:5000
echo 按 Ctrl+C 停止服务
echo.

cd /d "%~dp0"
python web/app.py
