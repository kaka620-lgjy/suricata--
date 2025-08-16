#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
远程服务器连接脚本
支持通过IP、端口、用户名、密码进行SSH连接
"""

import paramiko
import sys
import time
import argparse
import select
import json
import os
import base64
from typing import Optional, Tuple


class ConfigManager:
    """
    配置管理器
    用于保存和加载连接配置
    """
    
    def __init__(self, config_file: str = "connection_config.json"):
        """
        初始化配置管理器
        
        Args:
            config_file (str): 配置文件路径
        """
        self.config_file = config_file
    
    def _encode_password(self, password: str) -> str:
        """
        编码密码（简单的base64编码）
        
        Args:
            password (str): 原始密码
            
        Returns:
            str: 编码后的密码
        """
        return base64.b64encode(password.encode('utf-8')).decode('utf-8')
    
    def _decode_password(self, encoded_password: str) -> str:
        """
        解码密码
        
        Args:
            encoded_password (str): 编码后的密码
            
        Returns:
            str: 解码后的密码
        """
        try:
            return base64.b64decode(encoded_password.encode('utf-8')).decode('utf-8')
        except Exception:
            return ""
    
    def save_config(self, host: str, port: int, username: str, password: str = None):
        """
        保存连接配置
        
        Args:
            host (str): 服务器IP地址
            port (int): SSH端口
            username (str): 用户名
            password (str): 密码（可选，会进行简单编码后保存）
        """
        config = {
            "host": host,
            "port": port,
            "username": username,
            "last_used": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 如果提供了密码，进行编码后保存
        if password:
            config["password"] = self._encode_password(password)
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"✅ 配置已保存到 {self.config_file}")
        except Exception as e:
            print(f"⚠️ 配置保存失败: {e}")
    
    def load_config(self) -> Optional[dict]:
        """
        加载连接配置
        
        Returns:
            Optional[dict]: 配置信息，如果文件不存在或读取失败返回None
        """
        if not os.path.exists(self.config_file):
            return None
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 如果有保存的密码，进行解码
            if "password" in config:
                config["password"] = self._decode_password(config["password"])
            
            return config
        except Exception as e:
            print(f"⚠️ 配置加载失败: {e}")
            return None
    
    def get_last_config(self) -> Optional[dict]:
        """
        获取上次的配置信息
        
        Returns:
            Optional[dict]: 上次的配置信息
        """
        config = self.load_config()
        if config:
            print(f"📋 发现上次配置 (使用时间: {config.get('last_used', '未知')})")
            print(f"   服务器: {config.get('host', 'N/A')}:{config.get('port', 'N/A')}")
            print(f"   用户: {config.get('username', 'N/A')}")
            if config.get('password'):
                print(f"   密码: {'*' * len(config.get('password', ''))} (已保存)")
            else:
                print(f"   密码: 未保存")
        return config


class RemoteServer:
    """
    远程服务器连接类
    提供SSH连接、命令执行等功能
    """
    
    def __init__(self, host: str, port: int = 22, username: str = None, password: str = None):
        """
        初始化远程服务器连接
        
        Args:
            host (str): 服务器IP地址
            port (int): SSH端口，默认22
            username (str): 用户名
            password (str): 密码
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        self.shell = None
        self.config_manager = ConfigManager()
    
    def connect(self, max_retries: int = 3, retry_delay: float = 2.0) -> bool:
        """
        建立SSH连接（带重试机制）
        
        Args:
            max_retries: 最大重试次数
            retry_delay: 重试延迟（秒）
        
        Returns:
            bool: 连接成功返回True，失败返回False
        """
        for attempt in range(max_retries):
            try:
                # 如果已经连接，先断开
                if self.client:
                    try:
                        self.client.close()
                    except:
                        pass
                
                # 创建SSH客户端
                self.client = paramiko.SSHClient()
                
                # 设置SSH客户端参数以提高连接稳定性
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                if attempt == 0:
                    print(f"正在连接到 {self.host}:{self.port}...")
                else:
                    print(f"正在重试连接 ({attempt + 1}/{max_retries})...")
                
                # 建立连接，增加超时时间和设置更多参数
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=30,  # 增加超时时间到30秒
                    banner_timeout=30,  # 设置banner超时
                    auth_timeout=30,  # 设置认证超时
                    look_for_keys=False,  # 不查找密钥文件，提高连接速度
                    allow_agent=False,  # 不使用SSH agent
                    compress=True  # 启用压缩
                )
                
                # 测试连接是否真正可用
                if self._test_connection():
                    print(f"✅ 成功连接到服务器 {self.host}")
                    
                    # 保存配置（包括密码）
                    self.config_manager.save_config(self.host, self.port, self.username, self.password)
                    
                    return True
                else:
                    raise Exception("连接测试失败")
                
            except paramiko.AuthenticationException:
                print("❌ 认证失败：用户名或密码错误")
                return False  # 认证错误不重试
                
            except (paramiko.SSHException, OSError, TimeoutError) as e:
                error_msg = str(e)
                if attempt < max_retries - 1:
                    print(f"⚠️ 连接失败: {error_msg}，{retry_delay}秒后重试...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # 递增延迟时间
                else:
                    print(f"❌ SSH连接失败：{error_msg}")
                    return False
                    
            except Exception as e:
                error_msg = str(e)
                if attempt < max_retries - 1:
                    print(f"⚠️ 连接异常: {error_msg}，{retry_delay}秒后重试...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5
                else:
                    print(f"❌ 连接失败：{error_msg}")
                    return False
        
        return False
    
    def _test_connection(self) -> bool:
        """
        测试SSH连接是否可用
        
        Returns:
            bool: 连接可用返回True
        """
        try:
            # 执行一个简单的命令来测试连接
            stdin, stdout, stderr = self.client.exec_command('echo "connection_test"', timeout=10)
            result = stdout.read().decode('utf-8').strip()
            return result == "connection_test"
        except Exception:
            return False
    
    def execute_command(self, command: str) -> Tuple[bool, str, str]:
        """
        执行远程命令
        
        Args:
            command (str): 要执行的命令
            
        Returns:
            Tuple[bool, str, str]: (是否成功, 标准输出, 错误输出)
        """
        if not self.client:
            return False, "", "未建立连接"
        
        try:
            print(f"执行命令: {command}")
            stdin, stdout, stderr = self.client.exec_command(command)
            
            # 获取输出
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            success = stdout.channel.recv_exit_status() == 0
            
            return success, output, error
            
        except Exception as e:
            return False, "", f"命令执行失败：{e}"
    
    def interactive_shell(self):
        """
        启动交互式shell
        """
        if not self.client:
            print("❌ 未建立连接")
            return
        
        try:
            print("启动交互式shell...")
            print("输入 'exit' 或 'quit' 退出")
            print("-" * 50)
            
            # 获取交互式shell
            self.shell = self.client.invoke_shell()
            self.shell.settimeout(0.1)
            
            # 等待shell准备就绪
            time.sleep(1)
            
            print("Shell已准备就绪，可以开始输入命令...")
            
            while True:
                try:
                    # 获取用户输入
                    user_input = input("$ ")
                    
                    if user_input.lower() in ['exit', 'quit']:
                        break
                    
                    if user_input.strip():
                        # 发送命令到远程shell
                        self.shell.send(user_input + '\n')
                        
                        # 等待输出
                        time.sleep(0.5)
                        
                        # 读取输出
                        while self.shell.recv_ready():
                            try:
                                output = self.shell.recv(4096).decode('utf-8', errors='ignore')
                                if output:
                                    print(output, end='', flush=True)
                            except Exception as e:
                                print(f"读取输出错误: {e}")
                                break
                
                except (EOFError, KeyboardInterrupt):
                    print("\n用户中断连接")
                    break
                except Exception as e:
                    print(f"输入错误: {e}")
                    break
                
        except KeyboardInterrupt:
            print("\n用户中断连接")
        except Exception as e:
            print(f"交互式shell错误：{e}")
        finally:
            if self.shell:
                try:
                    self.shell.close()
                except:
                    pass
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        上传文件到远程服务器
        
        Args:
            local_path (str): 本地文件路径
            remote_path (str): 远程文件路径
            
        Returns:
            bool: 上传成功返回True，失败返回False
        """
        if not self.client:
            print("❌ 未建立连接")
            return False
        
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            print(f"✅ 文件上传成功：{local_path} -> {remote_path}")
            return True
        except Exception as e:
            print(f"❌ 文件上传失败：{e}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        从远程服务器下载文件
        
        Args:
            remote_path (str): 远程文件路径
            local_path (str): 本地文件路径
            
        Returns:
            bool: 下载成功返回True，失败返回False
        """
        if not self.client:
            print("❌ 未建立连接")
            return False
        
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            print(f"✅ 文件下载成功：{remote_path} -> {local_path}")
            return True
        except Exception as e:
            print(f"❌ 文件下载失败：{e}")
            return False
    
    def disconnect(self):
        """
        断开连接
        """
        if self.shell:
            self.shell.close()
        if self.client:
            self.client.close()
        print("🔌 连接已断开")


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description='远程服务器连接工具')
    parser.add_argument('--host', help='服务器IP地址')
    parser.add_argument('--port', type=int, default=22, help='SSH端口 (默认: 22)')
    parser.add_argument('--username', help='用户名')
    parser.add_argument('--password', help='密码')
    parser.add_argument('--command', help='要执行的命令 (可选)')
    parser.add_argument('--interactive', action='store_true', help='启动交互式shell')
    parser.add_argument('--no-config', action='store_true', help='不使用上次的配置')
    
    args = parser.parse_args()
    
    # 创建配置管理器
    config_manager = ConfigManager()
    
    # 如果没有提供必要参数，尝试加载上次配置
    if not args.host or not args.username:
        last_config = config_manager.get_last_config()
        if last_config and not args.no_config:
            print("\n是否使用上次的配置？")
            use_last = input("使用上次配置? (y/n, 默认y): ").strip().lower()
            if use_last in ['', 'y', 'yes', '是']:
                args.host = args.host or last_config.get('host')
                args.port = args.port or last_config.get('port', 22)
                args.username = args.username or last_config.get('username')
                args.password = args.password or last_config.get('password')
                print(f"✅ 使用上次配置: {args.host}:{args.port} 用户: {args.username}")
                if args.password:
                    print(f"   密码: {'*' * len(args.password)} (已加载)")
            else:
                print("📝 请输入新的连接信息")
    
    # 如果仍然缺少必要参数，提示用户输入
    if not args.host:
        args.host = input("请输入服务器IP地址: ").strip()
        if not args.host:
            print("❌ IP地址不能为空")
            sys.exit(1)
    
    if not args.username:
        args.username = input("请输入用户名: ").strip()
        if not args.username:
            print("❌ 用户名不能为空")
            sys.exit(1)
    
    if not args.password:
        args.password = input("请输入密码: ").strip()
        if not args.password:
            print("❌ 密码不能为空")
            sys.exit(1)
    
    # 创建远程服务器连接对象
    server = RemoteServer(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password
    )
    
    # 建立连接
    if not server.connect():
        sys.exit(1)
    
    try:
        if args.command:
            # 执行指定命令
            success, output, error = server.execute_command(args.command)
            if success:
                print("命令执行成功:")
                print(output)
            else:
                print("命令执行失败:")
                print(error)
        elif args.interactive:
            # 启动交互式shell
            server.interactive_shell()
        else:
            # 默认启动交互式shell
            server.interactive_shell()
    
    except KeyboardInterrupt:
        print("\n用户中断程序")
    finally:
        server.disconnect()


if __name__ == "__main__":
    # 如果没有命令行参数，使用交互式输入
    if len(sys.argv) == 1:
        print("远程服务器连接工具")
        print("=" * 30)
        
        # 创建配置管理器
        config_manager = ConfigManager()
        
        # 尝试加载上次配置
        last_config = config_manager.get_last_config()
        
        if last_config:
            print("\n是否使用上次的配置？")
            use_last = input("使用上次配置? (y/n, 默认y): ").strip().lower()
            
            if use_last in ['', 'y', 'yes', '是']:
                # 使用上次配置
                host = last_config.get('host')
                port = last_config.get('port', 22)
                username = last_config.get('username')
                password = last_config.get('password')
                
                print(f"✅ 使用上次配置:")
                print(f"   服务器: {host}:{port}")
                print(f"   用户: {username}")
                
                if password:
                    print(f"   密码: {'*' * len(password)} (已加载)")
                    # 询问是否使用保存的密码
                    use_saved_password = input("使用保存的密码? (y/n, 默认y): ").strip().lower()
                    if use_saved_password not in ['', 'y', 'yes', '是']:
                        password = input("请输入新密码: ").strip()
                        if not password:
                            print("❌ 密码不能为空")
                            sys.exit(1)
                else:
                    # 没有保存的密码，需要输入
                    password = input("请输入密码: ").strip()
                    if not password:
                        print("❌ 密码不能为空")
                        sys.exit(1)
            else:
                # 输入新配置
                host = input("请输入服务器IP地址: ").strip()
                if not host:
                    print("❌ IP地址不能为空")
                    sys.exit(1)
                
                port_input = input("请输入SSH端口 (默认22): ").strip()
                port = int(port_input) if port_input else 22
                
                username = input("请输入用户名: ").strip()
                if not username:
                    print("❌ 用户名不能为空")
                    sys.exit(1)
                
                password = input("请输入密码: ").strip()
                if not password:
                    print("❌ 密码不能为空")
                    sys.exit(1)
        else:
            # 没有上次配置，输入新配置
            host = input("请输入服务器IP地址: ").strip()
            if not host:
                print("❌ IP地址不能为空")
                sys.exit(1)
            
            port_input = input("请输入SSH端口 (默认22): ").strip()
            port = int(port_input) if port_input else 22
            
            username = input("请输入用户名: ").strip()
            if not username:
                print("❌ 用户名不能为空")
                sys.exit(1)
            
            password = input("请输入密码: ").strip()
            if not password:
                print("❌ 密码不能为空")
                sys.exit(1)
        
        server = RemoteServer(host, port, username, password)
        
        if server.connect():
            try:
                server.interactive_shell()
            except KeyboardInterrupt:
                print("\n用户中断程序")
            finally:
                server.disconnect()
    else:
        main() 