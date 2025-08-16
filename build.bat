@echo off
chcp 65001 >nul
echo ======================================
echo Suricata规则管理器 - 快速打包工具
echo ======================================
echo.

echo 安装依赖...
pip install -r requirements.txt

echo.
echo 开始打包...
python build_exe.py

echo.
echo 打包完成！
pause



