@echo off
chcp 65001 >nul
echo ======================================
echo 安装 Suricata规则管理器 打包依赖
echo ======================================
echo.

echo 正在安装依赖包...
echo.

pip install paramiko>=2.8.0
echo ✓ paramiko 安装完成

pip install pyinstaller>=5.0
echo ✓ pyinstaller 安装完成

echo.
echo ======================================
echo 依赖安装完成！
echo 现在可以运行 build.bat 开始打包
echo ======================================
pause



