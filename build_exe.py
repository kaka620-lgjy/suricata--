#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata规则管理器 - exe打包脚本
使用PyInstaller将Python项目打包为Windows可执行文件
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def check_requirements():
    """检查打包环境"""
    print("检查打包环境...")
    
    # 检查Python版本
    if sys.version_info < (3, 6):
        print("错误：需要Python 3.6或更高版本")
        return False
    
    # 检查PyInstaller是否安装
    try:
        import PyInstaller
        print(f"PyInstaller版本: {PyInstaller.__version__}")
    except ImportError:
        print("错误：未安装PyInstaller，请运行: pip install pyinstaller")
        return False
    
    # 检查paramiko是否安装
    try:
        import paramiko
        print(f"paramiko版本: {paramiko.__version__}")
    except ImportError:
        print("错误：未安装paramiko，请运行: pip install paramiko")
        return False
    
    return True

def clean_build():
    """清理构建目录"""
    print("清理构建目录...")
    dirs_to_clean = ['build', 'dist', '__pycache__']
    
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"已删除目录: {dir_name}")
    
    # 清理spec文件
    spec_files = [f for f in os.listdir('.') if f.endswith('.spec')]
    for spec_file in spec_files:
        os.remove(spec_file)
        print(f"已删除文件: {spec_file}")

def create_spec_file():
    """创建PyInstaller spec文件"""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['suricata_rules_manager.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('connection_config.json', '.'),
        ('suricata-ids.rules', '.'),
    ],
    hiddenimports=[
        'paramiko',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'tkinter.scrolledtext',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SuricataRulesManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 设为False隐藏控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # 可以添加icon='icon.ico'来设置程序图标
)
'''
    
    with open('suricata_manager.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print("已创建spec文件: suricata_manager.spec")

def build_executable():
    """构建可执行文件"""
    print("开始构建可执行文件...")
    
    try:
        # 使用spec文件构建
        cmd = [sys.executable, '-m', 'PyInstaller', 'suricata_manager.spec']
        print(f"执行命令: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        
        if result.returncode == 0:
            print("构建成功！")
            print("可执行文件位置: dist/SuricataRulesManager.exe")
            return True
        else:
            print("构建失败！")
            print("错误输出:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"构建过程中出错: {e}")
        return False

def create_dist_package():
    """创建发布包"""
    print("创建发布包...")
    
    dist_dir = Path('dist')
    if not dist_dir.exists():
        print("错误：dist目录不存在")
        return
    
    exe_file = dist_dir / 'SuricataRulesManager.exe'
    if not exe_file.exists():
        print("错误：可执行文件不存在")
        return
    
    # 创建发布包目录
    package_dir = dist_dir / 'SuricataRulesManager_Package'
    package_dir.mkdir(exist_ok=True)
    
    # 复制可执行文件
    shutil.copy2(exe_file, package_dir)
    
    # 复制必要的配置文件（如果存在的话）
    files_to_copy = ['suricata-ids.rules', 'README.md']
    for file_name in files_to_copy:
        if os.path.exists(file_name):
            shutil.copy2(file_name, package_dir)
    
    # 创建使用说明
    readme_content = '''# Suricata 规则管理器

## 使用说明

1. 双击 SuricataRulesManager.exe 启动程序
2. 程序将自动加载 suricata-ids.rules 文件中的规则
3. 可以通过界面进行规则的查看、编辑、添加和删除操作
4. 支持远程服务器连接功能

## 注意事项

- 首次运行时，程序会在当前目录创建配置文件
- 请确保有足够的权限读写规则文件
- 如需连接远程服务器，请配置正确的SSH连接信息

## 文件说明

- SuricataRulesManager.exe: 主程序
- suricata-ids.rules: Suricata规则文件
- connection_config.json: 连接配置文件（程序运行时自动生成）
'''
    
    with open(package_dir / '使用说明.txt', 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"发布包已创建: {package_dir}")
    print("包含文件:")
    for item in package_dir.iterdir():
        print(f"  - {item.name}")

def main():
    """主函数"""
    print("=" * 50)
    print("Suricata规则管理器 - exe打包工具")
    print("=" * 50)
    
    # 检查环境
    if not check_requirements():
        print("环境检查失败，请安装必要的依赖后重试")
        input("按任意键退出...")
        return
    
    # 清理构建目录
    clean_build()
    
    # 创建spec文件
    create_spec_file()
    
    # 构建可执行文件
    if build_executable():
        print("\n构建完成！")
        
        # 创建发布包
        create_dist_package()
        
        print("\n=" * 50)
        print("打包成功完成！")
        print("可执行文件: dist/SuricataRulesManager.exe")
        print("发布包: dist/SuricataRulesManager_Package/")
        print("=" * 50)
    else:
        print("构建失败，请检查错误信息")
    
    input("按任意键退出...")

if __name__ == "__main__":
    main()



