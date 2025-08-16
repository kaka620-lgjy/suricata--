# -*- coding: utf-8 -*-
"""
Suricata IDS 规则管理器
用于显示、编辑、删除和添加 Suricata 规则

重构优化版本 - 提升代码质量和维护性
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import re
import logging
import subprocess
import threading
import time
import socket
import platform
from datetime import datetime
from typing import List, Optional, Dict, Tuple, Any


# ==================== 配置常量 ====================
class AppConfig:
    """应用配置常量"""
    # 窗口配置
    MAIN_WINDOW_SIZE = "1400x800"
    DIALOG_WINDOW_SIZE = "600x400"
    RULE_DIALOG_SIZE = "800x400"
    SERVER_CONFIG_SIZE = "500x400"
    
    # 文件配置
    DEFAULT_RULES_FILE = "suricata-ids.rules"
    LOG_FILE = "suricata_manager.log"
    TEMP_RULES_FILE = "temp_suricata_rules.rules"
    CONFIG_FILE = "connection_config.json"
    
    # UI配置
    TREE_HEIGHT = 20
    ALERT_TREE_HEIGHT = 15
    MAX_DISPLAY_LENGTH = 100
    ALERT_MAX_DISPLAY_LENGTH = 50
    
    # 列宽配置
    COLUMN_WIDTHS = {
        'line_number': 60,
        'rule_content': 800,
        'rule_type': 100,
        'sid': 100,
        'alert_message': 300,
        'priority': 80,
        'protocol': 80,
        'src_ip': 120,
        'src_port': 80,
        'dst_ip': 120,
        'dst_port': 80,
        'count': 60
    }
    
    # 搜索选项
    SEARCH_SCOPES = ["全部", "规则内容", "SID", "类型", "消息"]
    FILTER_TYPES = ["全部", "告警", "丢弃", "拒绝", "注释", "其他"]
    PRIORITY_FILTERS = ["全部", "1", "2", "3"]
    PROTOCOL_FILTERS = ["全部", "TCP", "UDP", "ICMP"]
    
    # 远程服务器配置
    DEFAULT_SSH_PORT = 22
    DEFAULT_REMOTE_PATH = "/var/lib/suricata/rules/suricata.rules"
    TEMP_REMOTE_PATH = "/tmp"
    
    # 超时配置
    COMMAND_TIMEOUT = 300
    CONNECTION_TIMEOUT = 10
    
    # 文件类型
    RULE_FILE_TYPES = [("规则文件", "*.rules"), ("所有文件", "*.*")]
    PCAP_FILE_TYPES = [("数据包文件", "*.pcap *.pcapng"), ("所有文件", "*.*")]
    KEY_FILE_TYPES = [("私钥文件", "*.pem *.key"), ("所有文件", "*.*")]


class UIConstants:
    """UI界面常量"""
    # 标签页名称
    TAB_RULES_MANAGEMENT = "规则管理"
    TAB_ALERT_MODULE = "告警模块"
    TAB_FULL_LOG_MODULE = "全量日志"
    
    # 按钮文本
    BTN_SELECT_FILE = "选择文件"
    BTN_RELOAD = "重新加载"
    BTN_SAVE = "保存文件"
    BTN_COPY_ALL = "复制全部"
    BTN_PUSH_SERVER = "推送服务器"
    BTN_CLEAR_SEARCH = "清除搜索"
    BTN_ADD_RULE = "添加规则"
    BTN_DELETE_SELECTED = "删除选中"
    BTN_EDIT_SELECTED = "编辑选中"
    BTN_CLEAR_LIST = "清空列表"
    BTN_SELECT_PCAP = "选择数据包"
    BTN_START_ANALYSIS = "开始分析"
    BTN_REFRESH_ALERTS = "刷新告警"
    BTN_CLEAR_ALERTS = "清空告警"
    BTN_TEST_CONNECTION = "测试连接"
    BTN_OK = "确定"
    BTN_CANCEL = "取消"
    BTN_CLOSE = "关闭"
    BTN_BROWSE = "浏览"
    BTN_TOGGLE_LOG = "系统日志"
    BTN_REFRESH_FULL_LOG = "刷新日志"
    BTN_CLEAR_FULL_LOG = "清空日志"
    
    # 标签文本
    LABEL_RULES_FILE = "规则文件:"
    LABEL_SEARCH = "搜索:"
    LABEL_SEARCH_SCOPE = "搜索范围:"
    LABEL_TYPE_FILTER = "类型过滤:"
    LABEL_CURRENT_PCAP = "当前数据包:"
    LABEL_PRIORITY = "优先级:"
    LABEL_PROTOCOL = "协议:"
    LABEL_HOST = "主机地址:"
    LABEL_SSH_PORT = "SSH端口:"
    LABEL_USERNAME = "用户名:"
    LABEL_PASSWORD = "密码:"
    LABEL_REMOTE_PATH = "远程路径:"
    LABEL_KEY_FILE = "密钥文件:"
    LABEL_RULE_CONTENT = "规则内容:"
    LABEL_EVE_JSON_FILE = "EVE日志文件:"
    
    # 框架标题
    FRAME_FILE_OPERATIONS = "文件操作"
    FRAME_SEARCH_FILTER = "查询过滤"
    FRAME_RULES_LIST = "规则列表"
    FRAME_OPERATIONS = "操作"
    FRAME_PCAP_ANALYSIS = "数据包分析"
    FRAME_ALERT_FILTER = "告警过滤"
    FRAME_ALERT_LIST = "告警列表"
    FRAME_SERVER_INFO = "服务器信息"
    FRAME_AUTH_METHOD = "认证方式"
    FRAME_EVE_LOG_FILTER = "日志过滤"
    FRAME_EVE_LOG_LIST = "日志列表"
    FRAME_EVE_LOG_DETAIL = "日志详情"
    
    # 复选框文本
    CHECKBOX_MERGE_ALERTS = "合并相同告警"
    RADIO_PASSWORD_AUTH = "密码认证"
    RADIO_KEY_AUTH = "密钥文件认证"
    
    # 状态信息
    STATUS_READY = "就绪"
    STATUS_LOADING = "正在加载..."
    STATUS_CONNECTING = "正在连接服务器..."
    STATUS_UPLOADING = "正在上传规则文件..."
    STATUS_ANALYZING = "正在分析数据包..."
    STATUS_LOCAL_ANALYSIS = "正在运行本地Suricata分析..."
    STATUS_REMOTE_ANALYSIS = "正在运行远程Suricata分析..."
    STATUS_DOWNLOADING = "正在下载分析结果..."
    STATUS_RESTARTING = "正在重启Suricata服务..."


class RulePatterns:
    """规则解析相关的正则表达式模式"""
    # SID提取模式
    SID_PATTERNS = [
        r'sid:\s*(\d+)',
        r'sid:(\d+)',
        r'sid\s*:\s*(\d+)'
    ]
    
    # 消息提取模式
    MSG_PATTERN = r'msg:\s*"([^"]+)"'
    
    # 规则类型关键字
    RULE_TYPES = {
        'alert': '告警',
        'drop': '丢弃',
        'reject': '拒绝'
    }
    
    DEFAULT_RULE_TYPE = '其他'
    COMMENT_RULE_TYPE = '注释'
    UNKNOWN_RULE_TYPE = '未知'

# 导入远程连接模块
try:
    from remote_connect import RemoteServer, ConfigManager
    REMOTE_CONNECT_AVAILABLE = True
except ImportError:
    REMOTE_CONNECT_AVAILABLE = False
    print("警告: remote_connect 模块不可用，推送服务器功能将被禁用")


# ==================== 日志配置 ====================
def setup_logging() -> logging.Logger:
    """
    配置日志系统
    
    Returns:
        logging.Logger: 配置好的日志器
    """
    # 启动前清空系统日志文件
    try:
        if os.path.exists(AppConfig.LOG_FILE):
            with open(AppConfig.LOG_FILE, 'w', encoding='utf-8') as f:
                f.write('')  # 清空文件
            print(f"✅ 系统日志已清空: {AppConfig.LOG_FILE}")
    except Exception as e:
        print(f"⚠️ 清空系统日志失败: {e}")
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(AppConfig.LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    # 记录应用启动信息
    logger = logging.getLogger(__name__)
    # logger.info("🚀 Suricata规则管理器启动")
    # logger.info(f"📁 日志文件: {AppConfig.LOG_FILE}")
    # logger.info(f"⏰ 启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return logger


logger = setup_logging()


# ==================== 错误处理和工具类 ====================
class ErrorHandler:
    """错误处理工具类"""
    
    @staticmethod
    def handle_file_error(operation: str, file_path: str, error: Exception) -> None:
        """
        处理文件操作错误
        
        Args:
            operation: 操作类型
            file_path: 文件路径
            error: 异常对象
        """
        error_msg = f"{operation}文件失败: {file_path}\n错误: {str(error)}"
        logger.error(error_msg)
        messagebox.showerror("文件错误", error_msg)
    
    @staticmethod
    def handle_connection_error(host: str, port: int, error: Exception) -> None:
        """
        处理连接错误
        
        Args:
            host: 主机地址
            port: 端口号
            error: 异常对象
        """
        error_msg = f"连接失败: {host}:{port}\n错误: {str(error)}"
        logger.error(error_msg)
        messagebox.showerror("连接错误", error_msg)
    
    @staticmethod
    def handle_validation_error(field_name: str, message: str) -> None:
        """
        处理验证错误
        
        Args:
            field_name: 字段名
            message: 错误消息
        """
        error_msg = f"{field_name}: {message}"
        logger.warning(error_msg)
        messagebox.showwarning("验证错误", error_msg)


class FileHandler:
    """文件操作工具类"""
    
    @staticmethod
    def read_text_file(file_path: str, encoding: str = 'utf-8') -> List[str]:
        """
        读取文本文件
        
        Args:
            file_path: 文件路径
            encoding: 编码方式
            
        Returns:
            文件行列表
            
        Raises:
            FileNotFoundError: 文件不存在
            IOError: 读取失败
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.readlines()
        except Exception as e:
            raise IOError(f"读取文件失败: {e}")
    
    @staticmethod
    def write_text_file(file_path: str, content: List[str], encoding: str = 'utf-8') -> None:
        """
        写入文本文件
        
        Args:
            file_path: 文件路径
            content: 文件内容行列表
            encoding: 编码方式
            
        Raises:
            IOError: 写入失败
        """
        try:
            with open(file_path, 'w', encoding=encoding) as f:
                f.writelines(content)
        except Exception as e:
            raise IOError(f"写入文件失败: {e}")


class NetworkDiagnostic:
    """网络诊断工具类"""
    
    @staticmethod
    def ping_host(host: str, timeout: int = 5) -> bool:
        """
        Ping主机检查网络连通性
        
        Args:
            host: 主机地址
            timeout: 超时时间
            
        Returns:
            bool: 连通返回True
        """
        try:
            # 根据操作系统选择ping命令
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def check_port(host: str, port: int, timeout: int = 5) -> bool:
        """
        检查端口是否开放
        
        Args:
            host: 主机地址
            port: 端口号
            timeout: 超时时间
            
        Returns:
            bool: 端口开放返回True
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def diagnose_connection(host: str, port: int = 22) -> Dict[str, Any]:
        """
        诊断网络连接问题
        
        Args:
            host: 主机地址
            port: 端口号
            
        Returns:
            Dict: 诊断结果
        """
        result = {
            'host_reachable': False,
            'port_open': False,
            'dns_resolution': False,
            'suggestions': []
        }
        
        # DNS解析检查
        try:
            socket.gethostbyname(host)
            result['dns_resolution'] = True
        except Exception:
            result['suggestions'].append("DNS解析失败，请检查主机地址是否正确")
        
        # 网络连通性检查
        if NetworkDiagnostic.ping_host(host):
            result['host_reachable'] = True
        else:
            result['suggestions'].append("主机不可达，请检查网络连接或主机是否在线")
        
        # 端口检查
        if NetworkDiagnostic.check_port(host, port):
            result['port_open'] = True
        else:
            result['suggestions'].append(f"端口 {port} 不可达，请检查SSH服务是否运行")
        
        return result


class UIHelper:
    """UI辅助工具类"""
    
    @staticmethod
    def center_window(window: tk.Toplevel, parent: tk.Widget, width: int, height: int) -> None:
        """
        居中显示窗口
        
        Args:
            window: 要居中的窗口
            parent: 父窗口
            width: 窗口宽度
            height: 窗口高度
        """
        x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
        window.geometry(f"{width}x{height}+{x}+{y}")
    
    @staticmethod
    def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
        """
        截断文本
        
        Args:
            text: 原始文本
            max_length: 最大长度
            suffix: 后缀
            
        Returns:
            截断后的文本
        """
        if not text or len(text) <= max_length:
            return text
        return text[:max_length] + suffix


# ==================== 数据解析模块 ====================
class AlertParser:
    """
    告警信息解析类 - 负责解析Suricata告警日志
    
    支持解析fast.log格式的告警信息，提取关键字段
    """
    
    # 告警日志正则表达式模式
    ALERT_PATTERN = re.compile(
        r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+'  # 时间戳
        r'\[\*\*\]\s+'  # 分隔符
        r'\[(\d+):(\d+):(\d+)\]\s+'  # [gid:sid:rev]
        r'([^\[]+)\s+'  # 告警消息
        r'\[\*\*\]\s+'  # 分隔符
        r'\[Classification:\s*([^\]]+)\]\s+'  # 分类
        r'\[Priority:\s*(\d+)\]\s+'  # 优先级
        r'\{([^}]+)\}\s+'  # 协议
        r'([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)'  # 源IP:端口 -> 目标IP:端口
    )
    
    def __init__(self):
        """初始化告警解析器"""
        pass
    
    def parse_alert_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        解析单行告警信息
        
        Args:
            line: 告警行内容
            
        Returns:
            解析后的告警信息字典，失败时返回None
        """
        if not line or not line.strip():
            return None
        
        match = self.ALERT_PATTERN.match(line.strip())
        if not match:
            logger.warning(f"无法匹配告警行格式: {line[:100]}...")
            return None
        
        try:
            return {
                'timestamp': match.group(1),
                'gid': match.group(2),
                'sid': match.group(3),
                'rev': match.group(4),
                'message': match.group(5).strip(),
                'classification': match.group(6),
                'priority': int(match.group(7)),
                'protocol': match.group(8),
                'src_ip': match.group(9),
                'src_port': int(match.group(10)),
                'dst_ip': match.group(11),
                'dst_port': int(match.group(12)),
                'raw_line': line.strip()
            }
        except (ValueError, IndexError) as e:
            logger.error(f"解析告警行失败: {e}, 行内容: {line[:100]}...")
            return None
    
    def parse_fast_log(self, log_file: str) -> List[Dict[str, Any]]:
        """
        解析fast.log文件
        
        Args:
            log_file: fast.log文件路径
            
        Returns:
            告警信息列表
        """
        if not log_file or not os.path.exists(log_file):
            logger.warning(f"告警日志文件不存在: {log_file}")
            return []
        
        alerts = []
        failed_lines = 0
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    alert = self.parse_alert_line(line)
                    if alert:
                        alert['line_number'] = line_num
                        alerts.append(alert)
                    else:
                        failed_lines += 1
                        if failed_lines <= 5:  # 只记录前5个失败行
                            logger.debug(f"跳过无效告警行 {line_num}: {line[:50]}...")
            
            logger.info(f"解析完成: 成功 {len(alerts)} 行，失败 {failed_lines} 行")
            
        except (IOError, OSError) as e:
            logger.error(f"读取fast.log文件失败: {e}")
        except Exception as e:
            logger.error(f"解析fast.log文件时发生未知错误: {e}")
        
        return alerts


class EveLogParser:
    """
    EVE日志解析类 - 负责解析Suricata的eve.json文件
    
    支持解析JSON格式的事件日志，提取HTTP、DNS、TLS等各种事件信息
    """
    
    def __init__(self):
        """初始化EVE日志解析器"""
        pass
    
    def parse_eve_json(self, eve_file: str) -> List[Dict[str, Any]]:
        """
        解析eve.json文件
        
        Args:
            eve_file: eve.json文件路径
            
        Returns:
            事件信息列表
        """
        if not eve_file or not os.path.exists(eve_file):
            logger.warning(f"EVE日志文件不存在: {eve_file}")
            return []
        
        events = []
        failed_lines = 0
        
        try:
            import json
            
            with open(eve_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        event = json.loads(line.strip())
                        parsed_event = self.parse_event(event, line_num)
                        if parsed_event:
                            events.append(parsed_event)
                    except json.JSONDecodeError as e:
                        failed_lines += 1
                        if failed_lines <= 5:  # 只记录前5个失败行
                            logger.debug(f"跳过无效JSON行 {line_num}: {str(e)}")
                    except Exception as e:
                        failed_lines += 1
                        if failed_lines <= 5:
                            logger.debug(f"解析事件失败 {line_num}: {str(e)}")
            
            logger.info(f"EVE日志解析完成: 成功 {len(events)} 行，失败 {failed_lines} 行")
            
        except (IOError, OSError) as e:
            logger.error(f"读取eve.json文件失败: {e}")
        except Exception as e:
            logger.error(f"解析eve.json文件时发生未知错误: {e}")
        
        return events
    
    def parse_event(self, event: Dict[str, Any], line_num: int) -> Optional[Dict[str, Any]]:
        """
        解析单个事件
        
        Args:
            event: JSON事件对象
            line_num: 行号
            
        Returns:
            解析后的事件信息字典，失败时返回None
        """
        try:
            # 提取基本信息
            event_type = event.get('event_type', 'unknown')
            timestamp = event.get('timestamp', '')
            flow_id = event.get('flow_id', 0)
            
            # 提取网络信息
            src_ip = event.get('src_ip', '')
            src_port = event.get('src_port', 0)
            dest_ip = event.get('dest_ip', '')
            dest_port = event.get('dest_port', 0)
            proto = event.get('proto', '')
            
            # 根据事件类型进行特殊处理
            parsed_event = {
                'line_number': line_num,
                'event_type': event_type,
                'timestamp': timestamp,
                'flow_id': flow_id,
                'src_ip': src_ip,
                'src_port': src_port,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'proto': proto,
                'raw_event': event
            }
            
            # 处理HTTP事件
            if event_type == 'http':
                    http_info = event.get('http', {})
                    parsed_event.update({
                        'url': http_info.get('url', ''),
                        'hostname': http_info.get('hostname', ''),
                        'http_method': http_info.get('http_method', ''),
                        'status': http_info.get('status', 0),
                        'length': http_info.get('length', 0),
                        'http_user_agent': http_info.get('http_user_agent', ''),
                        'http_content_type': http_info.get('http_content_type', ''),
                        'http_refer': http_info.get('http_refer', ''),
                        'request_headers': http_info.get('request_headers', {}),
                        'response_headers': http_info.get('response_headers', {}),
                        'http_request_body': http_info.get('http_request_body', ''),
                        'http_response_body': http_info.get('http_response_body', '')
                    })
            
            # 处理DNS事件
            elif event_type == 'dns':
                dns_info = event.get('dns', {})
                parsed_event.update({
                    'dns_type': dns_info.get('type', ''),
                    'dns_rrname': dns_info.get('rrname', ''),
                    'dns_rrtype': dns_info.get('rrtype', ''),
                    'dns_rdata': dns_info.get('rdata', ''),
                    'dns_answers': dns_info.get('answers', [])
                })
            
            # 处理TLS事件
            elif event_type == 'tls':
                tls_info = event.get('tls', {})
                parsed_event.update({
                    'tls_version': tls_info.get('version', ''),
                    'tls_subject': tls_info.get('subject', ''),
                    'tls_issuerdn': tls_info.get('issuerdn', ''),
                    'tls_sni': tls_info.get('sni', ''),
                    'tls_fingerprint': tls_info.get('fingerprint', '')
                })
            
            # 处理告警事件
            elif event_type == 'alert':
                alert_info = event.get('alert', {})
                parsed_event.update({
                    'alert_signature': alert_info.get('signature', ''),
                    'alert_signature_id': alert_info.get('signature_id', 0),
                    'alert_category': alert_info.get('category', ''),
                    'alert_severity': alert_info.get('severity', 0)
                })
            
            # 处理文件事件
            elif event_type == 'fileinfo':
                file_info = event.get('fileinfo', {})
                parsed_event.update({
                    'filename': file_info.get('filename', ''),
                    'file_size': file_info.get('size', 0),
                    'file_type': file_info.get('magic', ''),
                    'file_hash': file_info.get('sha256', '')
                })
            
            return parsed_event
            
        except Exception as e:
            logger.error(f"解析事件失败: {e}, 事件内容: {event}")
            return None


# ==================== 主应用类 ====================
class SuricataRulesManager:
    """
    Suricata 规则管理器主类
    
    集成规则管理和告警分析功能的主应用程序
    """
    
    def __init__(self, root: tk.Tk):
        """
        初始化规则管理器
        
        Args:
            root: tkinter 根窗口
        """
        self.root = root
        self._setup_main_window()
        self._initialize_data()
        self._create_ui_components()
        self._load_initial_data()
    
    def _setup_main_window(self) -> None:
        """设置主窗口属性"""
        self.root.title("数据包异常检查")
        self.root.geometry(AppConfig.MAIN_WINDOW_SIZE)
    
    def _initialize_data(self) -> None:
        """初始化数据成员"""
        # 文件路径
        self.rules_file_path = AppConfig.DEFAULT_RULES_FILE
        self.rules_content: List[str] = []
        
        # 告警模块相关
        self.alert_parser = AlertParser()
        self.current_pcap_dir = ""
        self.alerts: List[Dict[str, Any]] = []
        
        # 全量日志模块相关
        self.eve_parser = EveLogParser()
        self.current_eve_file = ""
        self.eve_events: List[Dict[str, Any]] = []
        self.current_eve_event = None  # 当前选中的EVE事件，用于复制JSON
        
        # UI状态控制
        self.log_panel_visible = tk.BooleanVar(value=False)  # 默认隐藏系统日志
    
    def _create_ui_components(self) -> None:
        """创建UI组件"""
        self.create_widgets()
    
    def _load_initial_data(self) -> None:
        """加载初始数据"""
        self.load_rules_file()
    
    def create_widgets(self) -> None:
        """创建界面组件"""
        self._create_main_notebook()
        self._create_tab_frames()
        self._create_rules_interface()
        self._create_alerts_interface()
        self._create_full_log_interface()
    
    def _create_main_notebook(self) -> None:
        """创建主要的标签页容器和日志面板"""
        # 创建主容器，包含左侧功能区和右侧日志区
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 左侧功能区域
        left_frame = ttk.Frame(self.main_container)
        self.main_container.add(left_frame, weight=3)  # 左侧占3/4
        
        # 创建顶部控制栏，包含标签页选择和系统日志开关
        top_control_frame = ttk.Frame(left_frame)
        top_control_frame.pack(fill=tk.X, pady=(0, 5))
        
        # 左侧：标签页选择按钮区域
        tab_buttons_frame = ttk.Frame(top_control_frame)
        tab_buttons_frame.pack(side=tk.LEFT)
        
        # 创建标签页选择按钮
        self.current_tab = tk.StringVar(value=UIConstants.TAB_RULES_MANAGEMENT)
        
        self.rules_tab_button = ttk.Button(
            tab_buttons_frame,
            text=UIConstants.TAB_RULES_MANAGEMENT,
            command=lambda: self.switch_tab(UIConstants.TAB_RULES_MANAGEMENT)
        )
        self.rules_tab_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.alerts_tab_button = ttk.Button(
            tab_buttons_frame,
            text=UIConstants.TAB_ALERT_MODULE,
            command=lambda: self.switch_tab(UIConstants.TAB_ALERT_MODULE)
        )
        self.alerts_tab_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.full_log_tab_button = ttk.Button(
            tab_buttons_frame,
            text=UIConstants.TAB_FULL_LOG_MODULE,
            command=lambda: self.switch_tab(UIConstants.TAB_FULL_LOG_MODULE)
        )
        self.full_log_tab_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # 右侧：系统日志开关按钮
        log_toggle_frame = ttk.Frame(top_control_frame)
        log_toggle_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.log_toggle_button = ttk.Button(
            log_toggle_frame,
            text="显示" + UIConstants.BTN_TOGGLE_LOG,
            command=self.toggle_log_panel
        )
        self.log_toggle_button.pack(side=tk.RIGHT)
        
        # 创建内容区域容器
        self.content_frame = ttk.Frame(left_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # 右侧日志区域
        self.right_frame = ttk.Frame(self.main_container)
        # 初始状态不添加到PanedWindow，因为默认隐藏
        
        # 创建日志面板（但不立即显示）
        self._create_log_panel(self.right_frame)
    
    def _create_tab_frames(self) -> None:
        """创建标签页框架"""
        # 规则管理标签页
        self.rules_frame = ttk.Frame(self.content_frame)
        
        # 告警模块标签页
        self.alerts_frame = ttk.Frame(self.content_frame)
        
        # 全量日志模块标签页
        self.full_log_frame = ttk.Frame(self.content_frame)
        
        # 初始显示规则管理页面
        self.rules_frame.pack(fill=tk.BOTH, expand=True)
        self._update_tab_buttons(UIConstants.TAB_RULES_MANAGEMENT)
    
    def _create_rules_interface(self) -> None:
        """创建规则管理界面"""
        self.create_rules_widgets()
    
    def _create_alerts_interface(self) -> None:
        """创建告警模块界面"""
        self.create_alerts_widgets()
    
    def _create_full_log_interface(self) -> None:
        """创建全量日志模块界面"""
        self.create_full_log_widgets()
    
    def _create_log_panel(self, parent: tk.Widget) -> None:
        """
        创建日志面板
        
        Args:
            parent: 父组件
        """
        # 日志面板标题框架
        log_frame = ttk.LabelFrame(parent, text="系统日志", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # 日志控制按钮区域
        log_control_frame = ttk.Frame(log_frame)
        log_control_frame.pack(fill=tk.X, pady=(0, 5))
        
        # 刷新按钮
        ttk.Button(log_control_frame, text="刷新日志", command=self.refresh_log).pack(side=tk.LEFT, padx=(0, 5))
        
        # 清空按钮
        ttk.Button(log_control_frame, text="清空显示", command=self.clear_log_display).pack(side=tk.LEFT, padx=(0, 5))
        
        # 自动刷新选项
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_control_frame, text="自动刷新", variable=self.auto_refresh_var).pack(side=tk.LEFT, padx=(0, 5))
        
        # 只显示重点日志
        self.focus_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            log_control_frame,
            text="只显示重点",
            variable=self.focus_only_var,
            command=self.refresh_log
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # 显示行数控制
        ttk.Label(log_control_frame, text="显示行数:").pack(side=tk.LEFT, padx=(10, 5))
        self.log_lines_var = tk.StringVar(value="100")
        log_lines_combo = ttk.Combobox(log_control_frame, textvariable=self.log_lines_var, 
                                     values=["50", "100", "200", "500", "1000"], 
                                     width=8, state="readonly")
        log_lines_combo.pack(side=tk.LEFT)
        log_lines_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_log())
        
        # 日志显示区域
        log_display_frame = ttk.Frame(log_frame)
        log_display_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # 创建日志文本框
        self.log_text = scrolledtext.ScrolledText(
            log_display_frame, 
            height=25, 
            width=50,
            font=("Consolas", 9),  # 使用等宽字体
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 日志状态标签
        self.log_status_var = tk.StringVar(value="日志就绪")
        log_status_label = ttk.Label(log_frame, textvariable=self.log_status_var, relief=tk.SUNKEN)
        log_status_label.pack(fill=tk.X, pady=(5, 0))
        
        # 初始化日志相关变量
        self.log_file_path = AppConfig.LOG_FILE
        self.last_log_size = 0
        
        # 启动日志监控
        self.start_log_monitoring()
    
    def toggle_log_panel(self) -> None:
        """切换系统日志面板的显示/隐藏状态"""
        current_state = self.log_panel_visible.get()
        
        if current_state:
            # 当前显示，需要隐藏
            try:
                self.main_container.remove(self.right_frame)
                self.log_panel_visible.set(False)
                self.log_toggle_button.config(text="显示" + UIConstants.BTN_TOGGLE_LOG)
            except tk.TclError:
                # 如果面板不在容器中，忽略错误
                pass
        else:
            # 当前隐藏，需要显示
            self.main_container.add(self.right_frame, weight=1)
            self.log_panel_visible.set(True)
            self.log_toggle_button.config(text="隐藏" + UIConstants.BTN_TOGGLE_LOG)
            # 刷新日志显示
            self.refresh_log()
    
    def switch_tab(self, tab_name: str) -> None:
        """切换标签页"""
        # 隐藏所有标签页
        self.rules_frame.pack_forget()
        self.alerts_frame.pack_forget()
        self.full_log_frame.pack_forget()
        
        # 显示选中的标签页
        if tab_name == UIConstants.TAB_RULES_MANAGEMENT:
            self.rules_frame.pack(fill=tk.BOTH, expand=True)
        elif tab_name == UIConstants.TAB_ALERT_MODULE:
            self.alerts_frame.pack(fill=tk.BOTH, expand=True)
        elif tab_name == UIConstants.TAB_FULL_LOG_MODULE:
            self.full_log_frame.pack(fill=tk.BOTH, expand=True)
        
        # 更新当前标签页状态
        self.current_tab.set(tab_name)
        self._update_tab_buttons(tab_name)
    
    def _update_tab_buttons(self, active_tab: str) -> None:
        """更新标签页按钮的视觉状态"""
        # 重置所有按钮状态
        self.rules_tab_button.state(['!pressed'])
        self.alerts_tab_button.state(['!pressed'])
        self.full_log_tab_button.state(['!pressed'])
        
        # 设置活动按钮状态
        if active_tab == UIConstants.TAB_RULES_MANAGEMENT:
            self.rules_tab_button.state(['pressed'])
        elif active_tab == UIConstants.TAB_ALERT_MODULE:
            self.alerts_tab_button.state(['pressed'])
        elif active_tab == UIConstants.TAB_FULL_LOG_MODULE:
            self.full_log_tab_button.state(['pressed'])
    
    def create_rules_widgets(self):
        """
        创建规则管理界面组件
        """
        # 主框架
        main_frame = ttk.Frame(self.rules_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.rules_frame.columnconfigure(0, weight=1)
        self.rules_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # 文件操作区域
        file_frame = ttk.LabelFrame(main_frame, text="文件操作", padding="5")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # 文件路径显示
        self.file_path_var = tk.StringVar(value=self.rules_file_path)
        ttk.Label(file_frame, text="规则文件:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=50).grid(row=0, column=1, padx=(5, 5))
        
        # 按钮区域
        button_frame = ttk.Frame(file_frame)
        button_frame.grid(row=0, column=2, padx=(5, 0))
        
        # 第一行按钮
        button_row1 = ttk.Frame(button_frame)
        button_row1.pack(side=tk.TOP, pady=2)
        ttk.Button(button_row1, text="选择文件", command=self.select_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_row1, text="重新加载", command=self.load_rules_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_row1, text="保存文件", command=self.save_rules_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_row1, text="复制全部", command=self.copy_all_rules).pack(side=tk.LEFT, padx=(0, 5))
        if REMOTE_CONNECT_AVAILABLE:
            ttk.Button(button_row1, text="推送服务器", command=self.push_to_server).pack(side=tk.LEFT, padx=(0, 5))
        else:
            ttk.Button(button_row1, text="推送服务器", command=self.push_to_server_disabled, state="disabled").pack(side=tk.LEFT, padx=(0, 5))
        
        # 第二行按钮（现在为空，可以删除或保留以备将来使用）
        # button_row2 = ttk.Frame(button_frame)
        # button_row2.pack(side=tk.TOP, pady=2)
        
        # 查询区域
        search_frame = ttk.LabelFrame(main_frame, text="查询过滤", padding="5")
        search_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        search_frame.columnconfigure(1, weight=1)
        
        # 搜索框
        ttk.Label(search_frame, text="搜索:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.search_entry.bind('<KeyRelease>', self.on_search_change)
        
        # 搜索选项
        options_frame = ttk.Frame(search_frame)
        options_frame.grid(row=0, column=2, padx=(10, 0))
        
        # 搜索范围选择
        ttk.Label(options_frame, text="搜索范围:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_scope = tk.StringVar(value="全部")
        scope_combo = ttk.Combobox(options_frame, textvariable=self.search_scope, 
                                  values=["全部", "规则内容", "SID", "类型", "消息"], 
                                  width=10, state="readonly")
        scope_combo.pack(side=tk.LEFT, padx=(0, 10))
        scope_combo.bind('<<ComboboxSelected>>', self.on_search_change)
        
        # 过滤选项
        ttk.Label(options_frame, text="类型过滤:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_type = tk.StringVar(value="全部")
        filter_combo = ttk.Combobox(options_frame, textvariable=self.filter_type,
                                   values=["全部", "告警", "丢弃", "拒绝", "注释", "其他"],
                                   width=8, state="readonly")
        filter_combo.pack(side=tk.LEFT, padx=(0, 10))
        filter_combo.bind('<<ComboboxSelected>>', self.on_search_change)
        
        # 清除搜索按钮
        ttk.Button(options_frame, text="清除搜索", command=self.clear_search).pack(side=tk.LEFT)
        
        # 规则列表区域
        rules_frame = ttk.LabelFrame(main_frame, text="规则列表", padding="5")
        rules_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        rules_frame.columnconfigure(0, weight=1)
        rules_frame.rowconfigure(0, weight=1)
        
        # 创建规则列表
        self.create_rules_list(rules_frame)
        
        # 操作按钮区域
        actions_frame = ttk.LabelFrame(main_frame, text="操作", padding="5")
        actions_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(actions_frame, text="添加规则", command=self.add_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="删除选中", command=self.delete_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="编辑选中", command=self.edit_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="清空列表", command=self.clear_rules).pack(side=tk.LEFT, padx=(0, 5))
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
    
    def create_alerts_widgets(self):
        """
        创建告警模块界面组件
        """
        # 主框架
        main_frame = ttk.Frame(self.alerts_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.alerts_frame.columnconfigure(0, weight=1)
        self.alerts_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # 数据包操作区域
        pcap_frame = ttk.LabelFrame(main_frame, text="数据包分析", padding="5")
        pcap_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # 当前数据包显示
        self.current_pcap_var = tk.StringVar(value="未选择数据包")
        ttk.Label(pcap_frame, text="当前数据包:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(pcap_frame, textvariable=self.current_pcap_var, width=50, state="readonly").grid(row=0, column=1, padx=(5, 5))
        
        # 分析模式选择
        ttk.Label(pcap_frame, text="分析模式:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.analysis_mode_var = tk.StringVar(value="workers")
        mode_frame = ttk.Frame(pcap_frame)
        mode_frame.grid(row=1, column=1, sticky=tk.W, padx=(5, 5), pady=(5, 0))
        
        ttk.Radiobutton(mode_frame, text="Workers模式", variable=self.analysis_mode_var, 
                       value="workers").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="AutoFP模式", variable=self.analysis_mode_var, 
                       value="autofp").pack(side=tk.LEFT)
        
        # 网络接口设置
        ttk.Label(pcap_frame, text="网络接口:").grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        self.network_interface_var = tk.StringVar(value="ens33")
        ttk.Entry(pcap_frame, textvariable=self.network_interface_var, width=15).grid(row=2, column=1, sticky=tk.W, padx=(5, 5), pady=(5, 0))
        
        # 发送速度设置
        ttk.Label(pcap_frame, text="发送速度(Mbps):").grid(row=3, column=0, sticky=tk.W, pady=(5, 0))
        self.replay_speed_var = tk.StringVar(value="50")  # 降低默认速度以减少丢包
        speed_combo = ttk.Combobox(pcap_frame, textvariable=self.replay_speed_var, 
                                 values=["10", "20", "50", "100", "200", "300"], 
                                 width=8, state="readonly")
        speed_combo.grid(row=3, column=1, sticky=tk.W, padx=(5, 5), pady=(5, 0))
        
        # 按钮区域
        pcap_button_frame = ttk.Frame(pcap_frame)
        pcap_button_frame.grid(row=0, column=2, padx=(5, 0), rowspan=4)
        
        ttk.Button(pcap_button_frame, text="选择数据包", command=self.select_pcap_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(pcap_button_frame, text="开始分析", command=self.start_analysis).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(pcap_button_frame, text="刷新告警", command=self.refresh_alerts).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(pcap_button_frame, text="清空告警", command=self.clear_alerts).pack(side=tk.LEFT, padx=(0, 5))
        
        # 告警过滤区域
        alert_filter_frame = ttk.LabelFrame(main_frame, text="告警过滤", padding="5")
        alert_filter_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        alert_filter_frame.columnconfigure(1, weight=1)
        
        # 搜索框
        ttk.Label(alert_filter_frame, text="搜索:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.alert_search_var = tk.StringVar()
        self.alert_search_entry = ttk.Entry(alert_filter_frame, textvariable=self.alert_search_var, width=40)
        self.alert_search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.alert_search_entry.bind('<KeyRelease>', self.on_alert_search_change)
        
        # 过滤选项
        alert_options_frame = ttk.Frame(alert_filter_frame)
        alert_options_frame.grid(row=0, column=2, padx=(10, 0))
        
        # 优先级过滤
        ttk.Label(alert_options_frame, text="优先级:").pack(side=tk.LEFT, padx=(0, 5))
        self.priority_filter = tk.StringVar(value="全部")
        priority_combo = ttk.Combobox(alert_options_frame, textvariable=self.priority_filter,
                                     values=["全部", "1", "2", "3"], width=8, state="readonly")
        priority_combo.pack(side=tk.LEFT, padx=(0, 10))
        priority_combo.bind('<<ComboboxSelected>>', self.on_alert_search_change)
        
        # 协议过滤
        ttk.Label(alert_options_frame, text="协议:").pack(side=tk.LEFT, padx=(0, 5))
        self.protocol_filter = tk.StringVar(value="全部")
        protocol_combo = ttk.Combobox(alert_options_frame, textvariable=self.protocol_filter,
                                     values=["全部", "TCP", "UDP", "ICMP"], width=8, state="readonly")
        protocol_combo.pack(side=tk.LEFT, padx=(0, 10))
        protocol_combo.bind('<<ComboboxSelected>>', self.on_alert_search_change)
        
        # 清除搜索按钮
        ttk.Button(alert_options_frame, text="清除搜索", command=self.clear_alert_search).pack(side=tk.LEFT, padx=(0, 10))
        
        # 告警合并选项
        self.merge_alerts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(alert_options_frame, text="合并相同告警", variable=self.merge_alerts_var, 
                       command=self.refresh_alerts_list).pack(side=tk.LEFT)
        
        # 告警列表区域
        alerts_list_frame = ttk.LabelFrame(main_frame, text="告警列表", padding="5")
        alerts_list_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        alerts_list_frame.columnconfigure(0, weight=1)
        alerts_list_frame.rowconfigure(0, weight=1)
        
        # 创建告警列表
        self.create_alerts_list(alerts_list_frame)
        
        # 告警状态栏
        self.alert_status_var = tk.StringVar(value="就绪")
        alert_status_bar = ttk.Label(main_frame, textvariable=self.alert_status_var, relief=tk.SUNKEN)
        alert_status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
    
    def create_full_log_widgets(self):
        """
        创建全量日志模块界面组件
        """
        # 主框架
        main_frame = ttk.Frame(self.full_log_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.full_log_frame.columnconfigure(0, weight=1)
        self.full_log_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # 日志过滤区域
        filter_frame = ttk.LabelFrame(main_frame, text="日志过滤", padding="5")
        filter_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        filter_frame.columnconfigure(1, weight=1)
        
        # 搜索框
        ttk.Label(filter_frame, text="搜索:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.eve_search_var = tk.StringVar()
        self.eve_search_entry = ttk.Entry(filter_frame, textvariable=self.eve_search_var, width=40)
        self.eve_search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.eve_search_entry.bind('<KeyRelease>', self.on_eve_search_change)
        
        # 过滤选项
        filter_options_frame = ttk.Frame(filter_frame)
        filter_options_frame.grid(row=0, column=2, padx=(10, 0))
        
        # 事件类型过滤
        ttk.Label(filter_options_frame, text="事件类型:").pack(side=tk.LEFT, padx=(0, 5))
        self.event_type_filter = tk.StringVar(value="全部")
        event_type_combo = ttk.Combobox(filter_options_frame, textvariable=self.event_type_filter,
                                       values=["全部", "http", "dns", "tls", "alert", "fileinfo", "flow", "stats"], 
                                       width=10, state="readonly")
        event_type_combo.pack(side=tk.LEFT, padx=(0, 10))
        event_type_combo.bind('<<ComboboxSelected>>', self.on_eve_search_change)
        
        # 协议过滤
        ttk.Label(filter_options_frame, text="协议:").pack(side=tk.LEFT, padx=(0, 5))
        self.eve_protocol_filter = tk.StringVar(value="全部")
        eve_protocol_combo = ttk.Combobox(filter_options_frame, textvariable=self.eve_protocol_filter,
                                         values=["全部", "TCP", "UDP", "ICMP"], width=8, state="readonly")
        eve_protocol_combo.pack(side=tk.LEFT, padx=(0, 5))
        eve_protocol_combo.bind('<<ComboboxSelected>>', self.on_eve_search_change)
        
        # 清除搜索按钮
        ttk.Button(filter_options_frame, text="清除搜索", command=self.clear_eve_search).pack(side=tk.LEFT)
        
        # 日志列表和详情区域（左右分栏，各占一半）
        log_content_frame = ttk.Frame(main_frame)
        log_content_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_content_frame.columnconfigure(0, weight=1)
        log_content_frame.columnconfigure(1, weight=1)
        log_content_frame.rowconfigure(0, weight=1)
        
        # 左侧：日志列表
        log_list_frame = ttk.LabelFrame(log_content_frame, text="日志列表", padding="5")
        log_list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        log_list_frame.columnconfigure(0, weight=1)
        log_list_frame.rowconfigure(0, weight=1)
        
        # 创建日志列表
        self.create_eve_log_list(log_list_frame)
        
        # 右侧：日志详情
        log_detail_frame = ttk.LabelFrame(log_content_frame, text="日志详情", padding="5")
        log_detail_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        log_detail_frame.columnconfigure(0, weight=1)
        log_detail_frame.rowconfigure(0, weight=1)
        
        # 创建日志详情显示区域
        self.create_eve_log_detail(log_detail_frame)
        
        # 全量日志状态栏
        self.eve_status_var = tk.StringVar(value="等待告警模块完成分析后自动加载EVE日志...")
        eve_status_bar = ttk.Label(main_frame, textvariable=self.eve_status_var, relief=tk.SUNKEN)
        eve_status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
    
    def create_rules_list(self, parent: tk.Widget) -> None:
        """
        创建规则列表组件
        
        Args:
            parent: 父组件
        """
        # 定义列结构
        columns = ("行号", "规则内容", "类型", "SID")
        column_widths = {
            "行号": AppConfig.COLUMN_WIDTHS['line_number'],
            "规则内容": AppConfig.COLUMN_WIDTHS['rule_content'],
            "类型": AppConfig.COLUMN_WIDTHS['rule_type'],
            "SID": AppConfig.COLUMN_WIDTHS['sid']
        }
        
        # 创建TreeView
        self.tree = ttk.Treeview(
            parent, 
            columns=columns, 
            show="headings", 
            height=AppConfig.TREE_HEIGHT
        )
        
        # 配置列标题和宽度
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths[col])
        
        # 创建滚动条
        scrollbar_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        # 布局组件
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # 绑定事件
        self.tree.bind("<Double-1>", self.on_double_click)
        
        # 配置网格权重
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
    
    def create_alerts_list(self, parent: tk.Widget) -> None:
        """
        创建告警列表组件
        
        Args:
            parent: 父组件
        """
        # 定义列结构
        columns = ("告警信息", "优先级", "协议", "源IP", "源端口", "目标IP", "目标端口", "SID", "次数")
        column_widths = {
            "告警信息": AppConfig.COLUMN_WIDTHS['alert_message'],
            "优先级": AppConfig.COLUMN_WIDTHS['priority'],
            "协议": AppConfig.COLUMN_WIDTHS['protocol'],
            "源IP": AppConfig.COLUMN_WIDTHS['src_ip'],
            "源端口": AppConfig.COLUMN_WIDTHS['src_port'],
            "目标IP": AppConfig.COLUMN_WIDTHS['dst_ip'],
            "目标端口": AppConfig.COLUMN_WIDTHS['dst_port'],
            "SID": AppConfig.COLUMN_WIDTHS['sid'],
            "次数": AppConfig.COLUMN_WIDTHS['count']
        }
        
        # 创建TreeView
        self.alerts_tree = ttk.Treeview(
            parent, 
            columns=columns, 
            show="headings", 
            height=AppConfig.ALERT_TREE_HEIGHT
        )
        
        # 配置列标题和宽度
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=column_widths[col])
        
        # 创建滚动条
        scrollbar_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        scrollbar_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        # 布局组件
        self.alerts_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # 绑定事件
        self.alerts_tree.bind("<Double-1>", self.on_alert_double_click)
        
        # 配置网格权重
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
    
    def create_eve_log_list(self, parent: tk.Widget) -> None:
        """
        创建EVE日志列表组件
        
        Args:
            parent: 父组件
        """
        # 定义列结构
        columns = ("源IP", "源端口", "目标IP", "目标端口", "URL/域名")
        column_widths = {
            "源IP": 120,
            "源端口": 80,
            "目标IP": 120,
            "目标端口": 80,
            "URL/域名": 300
        }
        
        # 创建TreeView
        self.eve_tree = ttk.Treeview(
            parent, 
            columns=columns, 
            show="headings", 
            height=AppConfig.ALERT_TREE_HEIGHT
        )
        
        # 配置列标题和宽度
        for col in columns:
            self.eve_tree.heading(col, text=col)
            self.eve_tree.column(col, width=column_widths[col])
        
        # 创建滚动条
        scrollbar_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.eve_tree.yview)
        scrollbar_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.eve_tree.xview)
        self.eve_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        # 布局组件
        self.eve_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # 绑定事件
        self.eve_tree.bind("<Double-1>", self.on_eve_double_click)
        self.eve_tree.bind("<<TreeviewSelect>>", self.on_eve_select)
        
        # 配置网格权重
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
    
    def create_eve_log_detail(self, parent: tk.Widget) -> None:
        """
        创建EVE日志详情显示组件
        
        Args:
            parent: 父组件
        """
        # 创建按钮框架
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(0, 5))
        
        # 创建复制按钮
        self.copy_json_button = ttk.Button(
            button_frame, 
            text="复制JSON", 
            command=self.copy_eve_json,
            state=tk.DISABLED  # 初始状态为禁用
        )
        self.copy_json_button.pack(side=tk.RIGHT, padx=(0, 5))
        
        # 创建详情文本框
        self.eve_detail_text = scrolledtext.ScrolledText(
            parent, 
            height=AppConfig.ALERT_TREE_HEIGHT, 
            width=50,
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.eve_detail_text.pack(fill=tk.BOTH, expand=True)
        
        # 初始显示提示信息
        self.eve_detail_text.insert(tk.END, "请选择左侧日志条目查看详细信息")
        self.eve_detail_text.config(state=tk.DISABLED)
    
    def load_rules_file(self) -> None:
        """加载规则文件"""
        try:
            self.rules_content = FileHandler.read_text_file(self.rules_file_path)
            
            # 重置搜索条件
            self._reset_search_filters()
            
            # 刷新显示
            self.refresh_rules_list()
            self.status_var.set(f"已加载 {len(self.rules_content)} 行规则")
            logger.info(f"成功加载规则文件: {self.rules_file_path}")
            
        except FileNotFoundError:
            ErrorHandler.handle_validation_error("文件路径", f"文件不存在: {self.rules_file_path}")
            self.status_var.set("文件不存在")
        except IOError as e:
            ErrorHandler.handle_file_error("加载", self.rules_file_path, e)
            self.status_var.set("加载失败")
    
    def _reset_search_filters(self) -> None:
        """重置搜索过滤条件"""
        self.search_var.set("")
        self.search_scope.set(AppConfig.SEARCH_SCOPES[0])  # "全部"
        self.filter_type.set(AppConfig.FILTER_TYPES[0])    # "全部"
    
    def refresh_rules_list(self):
        """
        刷新规则列表显示
        """
        # 清空现有项目
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 获取搜索和过滤条件
        search_text = self.search_var.get().lower()
        search_scope = self.search_scope.get()
        filter_type = self.filter_type.get()
        
        # 添加规则到列表（应用搜索和过滤）
        filtered_count = 0
        for i, line in enumerate(self.rules_content, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                # 注释或空行
                rule_type = "注释"
                sid = ""
                msg = ""
            else:
                # 解析规则
                rule_type, sid = self.parse_rule(line)
                msg = self.extract_message(line)
            
            # 应用类型过滤
            if filter_type != "全部" and rule_type != filter_type:
                continue
            
            # 应用搜索过滤
            if search_text:
                if not self.matches_search(line, rule_type, sid, msg, search_text, search_scope):
                    continue
            
            # 显示规则
            display_line = UIHelper.truncate_text(line, AppConfig.MAX_DISPLAY_LENGTH)
            self.tree.insert("", "end", values=(i, display_line, rule_type, sid))
            filtered_count += 1
        
        # 更新状态栏
        if search_text or filter_type != "全部":
            self.status_var.set(f"显示 {filtered_count} 条规则 (已过滤)")
        else:
            self.status_var.set(f"显示 {len(self.rules_content)} 条规则")
    
    def parse_rule(self, rule_line: str) -> Tuple[str, str]:
        """
        解析规则行，提取类型和SID
        
        Args:
            rule_line: 规则行内容
            
        Returns:
            规则类型和SID的元组
        """
        if not rule_line or not rule_line.strip():
            return RulePatterns.UNKNOWN_RULE_TYPE, ""
        
        try:
            # 提取SID
            sid = self._extract_sid(rule_line)
            
            # 提取规则类型
            rule_type = self._extract_rule_type(rule_line)
            
            return rule_type, sid
            
        except Exception as e:
            logger.error(f"解析规则时出错: {e}, 规则内容: {rule_line[:50]}...")
            return RulePatterns.UNKNOWN_RULE_TYPE, ""
    
    def _extract_sid(self, rule_line: str) -> str:
        """
        从规则行中提取SID
        
        Args:
            rule_line: 规则行内容
            
        Returns:
            SID字符串，未找到时返回空字符串
        """
        for pattern in RulePatterns.SID_PATTERNS:
            sid_match = re.search(pattern, rule_line, re.IGNORECASE)
            if sid_match:
                return sid_match.group(1)
        return ""
    
    def _extract_rule_type(self, rule_line: str) -> str:
        """
        从规则行中提取规则类型
        
        Args:
            rule_line: 规则行内容
            
        Returns:
            规则类型字符串
        """
        rule_line_lower = rule_line.lower()
        
        for keyword, type_name in RulePatterns.RULE_TYPES.items():
            if keyword in rule_line_lower:
                return type_name
        
        return RulePatterns.DEFAULT_RULE_TYPE
    
    def extract_message(self, rule_line: str) -> str:
        """
        从规则中提取消息内容
        
        Args:
            rule_line: 规则行内容
            
        Returns:
            消息内容字符串，未找到时返回空字符串
        """
        if not rule_line:
            return ""
        
        try:
            msg_match = re.search(RulePatterns.MSG_PATTERN, rule_line, re.IGNORECASE)
            return msg_match.group(1) if msg_match else ""
        except Exception as e:
            logger.debug(f"提取消息失败: {e}, 规则内容: {rule_line[:50]}...")
            return ""
    
    def matches_search(self, line: str, rule_type: str, sid: str, msg: str, search_text: str, search_scope: str) -> bool:
        """
        检查规则是否匹配搜索条件
        
        Args:
            line: 规则行内容
            rule_type: 规则类型
            sid: SID
            msg: 消息内容
            search_text: 搜索文本
            search_scope: 搜索范围
            
        Returns:
            bool: 是否匹配
        """
        if not search_text:
            return True
        
        search_text = search_text.lower()
        
        if search_scope == "全部":
            return (search_text in line.lower() or 
                   search_text in rule_type.lower() or 
                   search_text in sid.lower() or 
                   search_text in msg.lower())
        elif search_scope == "规则内容":
            return search_text in line.lower()
        elif search_scope == "SID":
            return search_text in sid.lower()
        elif search_scope == "类型":
            return search_text in rule_type.lower()
        elif search_scope == "消息":
            return search_text in msg.lower()
        
        return False
    
    def on_search_change(self, event=None):
        """
        搜索条件改变时的处理
        """
        self.refresh_rules_list()
    
    def clear_search(self):
        """
        清除搜索条件
        """
        self.search_var.set("")
        self.search_scope.set("全部")
        self.filter_type.set("全部")
        self.refresh_rules_list()
        self.status_var.set("搜索已清除")
    
    def select_file(self):
        """
        选择规则文件
        """
        file_path = filedialog.askopenfilename(
            title="选择 Suricata 规则文件",
            filetypes=[("规则文件", "*.rules"), ("所有文件", "*.*")]
        )
        
        if file_path:
            self.rules_file_path = file_path
            self.file_path_var.set(file_path)
            self.load_rules_file()
    
    def save_rules_file(self) -> None:
        """保存规则文件"""
        try:
            FileHandler.write_text_file(self.rules_file_path, self.rules_content)
            
            messagebox.showinfo("成功", "规则文件已保存")
            self.status_var.set("文件已保存")
            logger.info(f"成功保存规则文件: {self.rules_file_path}")
            
            # 保存后刷新显示
            self.refresh_rules_list()
            
        except IOError as e:
            ErrorHandler.handle_file_error("保存", self.rules_file_path, e)
            self.status_var.set("保存失败")
    
    def save_rules_file_silent(self) -> None:
        """静默保存规则文件（不弹出成功提示框）"""
        try:
            FileHandler.write_text_file(self.rules_file_path, self.rules_content)
            
            self.status_var.set("文件已保存")
            logger.info(f"成功保存规则文件: {self.rules_file_path}")
            
            # 保存后刷新显示
            self.refresh_rules_list()
            
        except IOError as e:
            # 静默处理错误，只记录日志，不弹出错误对话框
            logger.error(f"保存文件失败: {self.rules_file_path}, 错误: {str(e)}")
            self.status_var.set("保存失败")
            raise e  # 抛出异常以便调用者知道保存失败
    
    def add_rule(self):
        """
        添加新规则
        """
        dialog = RuleDialog(self.root, "添加新规则")
        if dialog.result:
            # 在列表末尾添加新规则
            self.rules_content.append(dialog.result + "\n")
            self.refresh_rules_list()
            self.status_var.set("已添加新规则")
    
    def delete_selected(self):
        """
        删除选中的规则
        """
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择要删除的规则")
            return
        
        if messagebox.askyesno("确认", "确定要删除选中的规则吗？"):
            # 获取选中的行号（从1开始）
            selected_rows = []
            for item in selected_items:
                row_num = int(self.tree.item(item)['values'][0])
                selected_rows.append(row_num)
            
            # 从后往前删除，避免索引变化
            selected_rows.sort(reverse=True)
            for row_num in selected_rows:
                if 0 < row_num <= len(self.rules_content):
                    del self.rules_content[row_num - 1]
            
            self.refresh_rules_list()
            self.status_var.set(f"已删除 {len(selected_rows)} 条规则")
    
    def edit_selected(self):
        """
        编辑选中的规则
        """
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择要编辑的规则")
            return
        
        if len(selected_items) > 1:
            messagebox.showwarning("警告", "一次只能编辑一条规则")
            return
        
        # 获取选中的行号
        row_num = int(self.tree.item(selected_items[0])['values'][0])
        if 0 < row_num <= len(self.rules_content):
            current_rule = self.rules_content[row_num - 1].strip()
            dialog = RuleDialog(self.root, "编辑规则", current_rule)
            
            if dialog.result:
                self.rules_content[row_num - 1] = dialog.result + "\n"
                self.refresh_rules_list()
                self.status_var.set("规则已更新")
    
    def clear_rules(self):
        """
        清空所有规则
        """
        if messagebox.askyesno("确认", "确定要清空所有规则吗？"):
            self.rules_content.clear()
            self.refresh_rules_list()
            self.status_var.set("已清空所有规则")
    
    def on_double_click(self, event):
        """
        双击事件处理
        """
        self.edit_selected()

    def copy_all_rules(self):
        """
        复制所有规则到剪贴板
        """
        try:
            # 获取所有规则内容
            rules_text = "".join(self.rules_content)
            
            if not rules_text.strip():
                messagebox.showwarning("警告", "没有规则内容可复制")
                return
            
            # 复制到剪贴板
            self.root.clipboard_clear()
            self.root.clipboard_append(rules_text)
            self.root.update()  # 确保剪贴板内容更新
            
            # 显示成功消息
            messagebox.showinfo("成功", f"已复制 {len(self.rules_content)} 行规则到剪贴板")
            self.status_var.set("规则已复制到剪贴板")
            
        except Exception as e:
            messagebox.showerror("错误", f"复制失败: {str(e)}")
            self.status_var.set("复制失败")

    def push_to_server_disabled(self):
        """
        推送服务器功能禁用时的提示
        """
        messagebox.showwarning("功能不可用", "remote_connect 模块不可用，推送服务器功能已被禁用。\n请确保 remote_connect.py 文件在同一目录下。")

    def push_to_server(self):
        """
        推送规则文件到服务器
        """
        if not REMOTE_CONNECT_AVAILABLE:
            messagebox.showerror("错误", "remote_connect 模块不可用")
            return
        
        # 检查是否有规则内容
        if not self.rules_content:
            messagebox.showwarning("警告", "没有规则内容可推送")
            return
        
        # 推送前自动保存文件
        try:
            self.save_rules_file_silent()
            logger.info("推送前自动保存规则文件成功")
        except Exception as e:
            logger.warning(f"推送前保存文件失败: {e}")
            # 保存失败时继续推送，不弹出询问对话框
            logger.info("保存失败，但继续进行推送")
        
        # 跳过规则语法检查（按用户要求）
        # 原来的语法检查代码已被注释，直接进行推送
        logger.info("跳过上传前规则语法检查，直接推送")
        
        # 尝试加载上次配置
        last_config = None
        if REMOTE_CONNECT_AVAILABLE:
            try:
                config_manager = ConfigManager()
                last_config = config_manager.load_config()
            except Exception as e:
                print(f"⚠️ 加载配置失败: {e}")
        
        # 如果没有上次配置，显示配置对话框
        if not last_config:
            config_dialog = ServerConfigDialog(self.root)
            if not config_dialog.result:
                return
            config = config_dialog.result
        else:
            # 使用上次配置
            config = {
                "host": last_config.get('host'),
                "port": last_config.get('port', 22),
                "username": last_config.get('username'),
                "password": last_config.get('password'),
                "remote_path": "/var/lib/suricata/rules/suricata.rules",
                "auth_method": "password",
                "key_path": ""
            }
        
        # 开始推送流程
        self.status_var.set("正在连接服务器...")
        self.root.update()
        
        try:
            # 创建连接对象
            if config['auth_method'] == 'key':
                # 密钥认证（目前使用密码认证，后续可以扩展）
                messagebox.showwarning("提示", "密钥认证功能正在开发中，请使用密码认证")
                return
            else:
                # 密码认证
                server = RemoteServer(
                    host=config['host'],
                    port=config['port'],
                    username=config['username'],
                    password=config['password']
                )
            
            # 建立连接（带重试机制）
            self.status_var.set("正在建立SSH连接...")
            self.root.update()
            
            if not server.connect(max_retries=3, retry_delay=2.0):
                # 进行网络诊断
                self.status_var.set("正在诊断网络连接...")
                self.root.update()
                
                diagnosis = NetworkDiagnostic.diagnose_connection(config['host'], config['port'])
                
                # 构建诊断报告
                diagnostic_info = "网络诊断结果：\n"
                diagnostic_info += f"- DNS解析: {'✅ 正常' if diagnosis['dns_resolution'] else '❌ 失败'}\n"
                diagnostic_info += f"- 主机连通性: {'✅ 可达' if diagnosis['host_reachable'] else '❌ 不可达'}\n"
                diagnostic_info += f"- SSH端口({config['port']}): {'✅ 开放' if diagnosis['port_open'] else '❌ 关闭'}\n"
                
                if diagnosis['suggestions']:
                    diagnostic_info += "\n建议的解决方案：\n"
                    for i, suggestion in enumerate(diagnosis['suggestions'], 1):
                        diagnostic_info += f"{i}. {suggestion}\n"
                
                error_msg = f"""❌ SSH连接失败

服务器信息：
- 主机: {config['host']}:{config['port']}
- 用户: {config['username']}

{diagnostic_info}
其他可能的解决方案：
• 确认SSH服务是否运行 (sudo systemctl status ssh)
• 检查防火墙设置
• 验证用户名和密码
• 检查SSH配置文件 (/etc/ssh/sshd_config)"""
                
                messagebox.showerror("连接失败", error_msg)
                self.status_var.set("连接失败")
                return
            
            self.status_var.set("正在上传规则文件...")
            self.root.update()
            
            # 创建临时文件
            temp_file = "temp_suricata_rules.rules"
            try:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.writelines(self.rules_content)
                
                # 上传文件
                if server.upload_file(temp_file, config['remote_path']):
                    success_msg = f"✅ 规则文件推送成功！服务器: {config['host']}:{config['port']}, 用户: {config['username']}, 路径: {config['remote_path']}, 总行数: {len(self.rules_content)} 行"
                    self.status_var.set("规则文件推送成功")
                    logger.info(success_msg)
                    
                    # 推送成功，无需重启Suricata服务
                    logger.info("规则文件推送成功")
                else:
                    error_msg = f"❌ 规则文件上传失败，服务器: {config['host']}:{config['port']}, 用户: {config['username']}, 路径: {config['remote_path']}"
                    logger.error(error_msg)
                    self.status_var.set("推送失败")
            
            finally:
                # 清理临时文件
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                
                # 断开连接
                server.disconnect()
        
        except Exception as e:
            error_msg = f"❌ 推送失败: {str(e)}, 服务器: {config.get('host', 'N/A')}:{config.get('port', 'N/A')}, 用户: {config.get('username', 'N/A')}"
            logger.error(error_msg)
            self.status_var.set("推送失败")
            logger.error(f"推送规则文件失败: {str(e)}")

    def restart_suricata_service(self, server):
        """
        重启Suricata服务
        
        Args:
            server: RemoteServer对象
        """
        try:
            self.status_var.set("正在重启Suricata服务...")
            self.root.update()
            
            # 尝试不同的重启命令
            restart_commands = [
                "sudo systemctl restart suricata",
                "sudo service suricata restart",
                "sudo /etc/init.d/suricata restart"
            ]
            
            success = False
            for command in restart_commands:
                try:
                    success, output, error = server.execute_command(command)
                    if success:
                        self.status_var.set("Suricata服务重启成功")
                        messagebox.showinfo("成功", "Suricata服务已重启")
                        break
                except:
                    continue
            
            if not success:
                messagebox.showwarning("警告", "无法自动重启Suricata服务，请手动重启")
                self.status_var.set("服务重启失败，请手动重启")
        
        except Exception as e:
            messagebox.showerror("错误", f"重启服务失败: {str(e)}")
            self.status_var.set("服务重启失败")
            logger.error(f"重启Suricata服务失败: {str(e)}")

    def select_pcap_file(self):
        """
        选择数据包文件
        """
        file_path = filedialog.askopenfilename(
            title="选择数据包文件",
            filetypes=[("数据包文件", "*.pcap *.pcapng"), ("所有文件", "*.*")]
        )
        
        if file_path:
            self.current_pcap_dir = os.path.dirname(file_path)
            self.current_pcap_var.set(os.path.basename(file_path))
            self.alert_status_var.set(f"已选择数据包: {os.path.basename(file_path)}")

    def start_analysis(self):
        """
        开始分析数据包
        """
        if not self.current_pcap_var.get() or self.current_pcap_var.get() == "未选择数据包":
            messagebox.showwarning("警告", "请先选择数据包文件")
            return
        
        pcap_file = os.path.join(self.current_pcap_dir, self.current_pcap_var.get())
        if not os.path.exists(pcap_file):
            messagebox.showerror("错误", "数据包文件不存在")
            return
        
        # 获取分析参数
        analysis_mode = self.analysis_mode_var.get()
        network_interface = self.network_interface_var.get()
        replay_speed = self.replay_speed_var.get()
        
        try:
            # 设置等待状态
            self.alert_status_var.set("正在准备分析...")
            self.root.update()
            
            # 禁用开始分析按钮防止重复点击
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Notebook):
                    for frame in widget.winfo_children():
                        self._disable_analysis_controls(frame, True)
            
            # 在新线程中进行分析以免阻塞UI
            analysis_thread = threading.Thread(
                target=self._run_analysis_thread,
                args=(pcap_file, analysis_mode, network_interface, replay_speed),
                daemon=True
            )
            analysis_thread.start()
            
        except Exception as e:
            messagebox.showerror("错误", f"分析启动失败: {str(e)}")
            self.alert_status_var.set("分析失败")
            self._enable_analysis_controls()
    
    def _disable_analysis_controls(self, parent, disable=True):
        """禁用/启用分析相关控件"""
        for child in parent.winfo_children():
            if isinstance(child, ttk.Button) and child.cget('text') == '开始分析':
                child.config(state='disabled' if disable else 'normal')
            elif hasattr(child, 'winfo_children'):
                self._disable_analysis_controls(child, disable)
    
    def _enable_analysis_controls(self):
        """启用分析控件"""
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Notebook):
                for frame in widget.winfo_children():
                    self._disable_analysis_controls(frame, False)
    
    def _run_analysis_thread(self, pcap_file: str, analysis_mode: str, network_interface: str, replay_speed: str):
        """在线程中运行分析"""
        try:
            # 使用新的分析方法
            self.analyze_pcap_with_new_method(pcap_file, analysis_mode, network_interface, replay_speed)
        except Exception as e:
            # 在主线程中显示错误
            self.root.after(0, lambda: messagebox.showerror("错误", f"分析失败: {str(e)}"))
            self.root.after(0, lambda: self.alert_status_var.set("分析失败"))
        finally:
            # 在主线程中重新启用控件
            self.root.after(0, self._enable_analysis_controls)

    def analyze_pcap_with_new_method(self, pcap_file: str, analysis_mode: str, network_interface: str, replay_speed: str):
        """
        使用新方法分析数据包：tcpreplay + suricata
        
        Args:
            pcap_file: 数据包文件路径
            analysis_mode: 分析模式 ('workers' 或 'autofp')
            network_interface: 网络接口名称
            replay_speed: tcpreplay发送速度(Mbps)
        """
        try:
            # 首先尝试本地分析
            if self._try_local_new_analysis(pcap_file, analysis_mode, network_interface, replay_speed):
                return
            
            # 如果本地分析失败，尝试远程分析
            if REMOTE_CONNECT_AVAILABLE:
                if self._try_remote_new_analysis(pcap_file, analysis_mode, network_interface, replay_speed):
                    return
            
            # 如果都失败了，显示错误信息
            self.root.after(0, lambda: messagebox.showerror("错误", 
                "无法进行数据包分析。\n\n可能的原因：\n1. Suricata或tcpreplay未安装\n2. 远程服务器连接失败\n3. 网络接口配置错误"))
            self.root.after(0, lambda: self.alert_status_var.set("分析失败"))
            
        except Exception as e:
            logger.error(f"分析失败: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("错误", f"分析失败: {str(e)}"))
            self.root.after(0, lambda: self.alert_status_var.set("分析失败"))
    
    def _try_local_new_analysis(self, pcap_file: str, analysis_mode: str, network_interface: str, replay_speed: str) -> bool:
        """
        尝试本地新方法分析
        
        Args:
            pcap_file: 数据包文件路径
            analysis_mode: 分析模式
            network_interface: 网络接口
            replay_speed: tcpreplay发送速度(Mbps)
            
        Returns:
            是否成功
        """
        try:
            # 检查本地工具是否可用
            if not self._check_local_tools():
                return False
            
            self.root.after(0, lambda: self.alert_status_var.set("正在启动本地Suricata..."))
            
            # 创建带时间戳的输出目录，避免多次分析时的文件冲突
            timestamp = int(time.time())
            output_dir = os.path.join(self.current_pcap_dir, f"suricata_output_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            
            # 构建suricata命令
            suricata_cmd = [
                "suricata",
                "-i", network_interface,
                "-c", "/etc/suricata/suricata.yaml",
                "-v",
                "-k", "none",
                "--runmode", analysis_mode,
                "-l", output_dir
            ]
            
            # 构建tcpreplay命令
            tcpreplay_cmd = [
                "tcpreplay",
                f"--mbps={replay_speed}",
                "--loop=0",
                "-i", network_interface,
                pcap_file
            ]
            
            self.root.after(0, lambda: self.alert_status_var.set(f"正在运行{analysis_mode}模式分析..."))
            
            # 启动suricata
            suricata_process = subprocess.Popen(
                suricata_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 等待一会让suricata启动
            time.sleep(3)
            
            # 运行tcpreplay
            tcpreplay_result = subprocess.run(
                tcpreplay_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # 等待suricata处理完成
            time.sleep(5)
            
            # 停止suricata
            try:
                suricata_process.terminate()
                suricata_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                suricata_process.kill()
            
            # 解析tcpreplay输出获取丢包率
            packet_loss_info = self._parse_tcpreplay_output(tcpreplay_result.stderr)
            
            # 处理分析结果
            return self._process_analysis_results(output_dir, packet_loss_info, analysis_mode)
            
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: self.alert_status_var.set("分析超时"))
            return False
        except Exception as e:
            logger.error(f"本地新方法分析失败: {str(e)}")
            return False
    
    def _check_local_tools(self) -> bool:
        """检查本地工具是否可用"""
        try:
            # 检查suricata
            subprocess.run(["suricata", "--version"], 
                         capture_output=True, check=True)
            # 检查tcpreplay
            subprocess.run(["tcpreplay", "--version"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _parse_tcpreplay_output(self, output: str) -> Dict[str, Any]:
        """
        解析tcpreplay输出获取丢包率信息
        
        Args:
            output: tcpreplay的stderr输出
            
        Returns:
            包含丢包率等信息的字典
        """
        packet_info = {
            'total_packets': 0,
            'successful_packets': 0,
            'failed_packets': 0,
            'packet_loss_rate': 0.0,
            'bytes_sent': 0,
            'duration': 0.0
        }
        
        try:
            import re
            logger.debug(f"开始解析tcpreplay输出，长度: {len(output)} 字符")
            logger.debug(f"tcpreplay原始输出:\n{output}")
            
            lines = output.split('\n')
            matched_lines = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 尝试多种tcpreplay输出格式
                # 格式1: Actual: 723 packets (90300 bytes) sent in 0.123456 seconds
                actual_match = re.search(r'Actual:\s*(\d+)\s+packets.*sent.*?(\d+(?:\.\d+)?)\s+seconds', line)
                if actual_match:
                    packet_info['total_packets'] = int(actual_match.group(1))
                    packet_info['duration'] = float(actual_match.group(2))
                    matched_lines.append(f"总数据包: {line}")
                    logger.debug(f"匹配到总数据包: {packet_info['total_packets']}")
                
                # 格式2: 723 packets sent successfully
                success_match = re.search(r'(\d+)\s+packets?\s+sent\s+successfully', line)
                if success_match:
                    packet_info['successful_packets'] = int(success_match.group(1))
                    matched_lines.append(f"成功发送: {line}")
                    logger.debug(f"匹配到成功发送: {packet_info['successful_packets']}")
                
                # 格式3: 59 packets failed to send
                failed_match = re.search(r'(\d+)\s+packets?\s+failed', line)
                if failed_match:
                    packet_info['failed_packets'] = int(failed_match.group(1))
                    matched_lines.append(f"发送失败: {line}")
                    logger.debug(f"匹配到发送失败: {packet_info['failed_packets']}")
                
                # 格式4: Attempted: 723 packets, sent: 664 packets, failed: 59 packets
                attempted_match = re.search(r'Attempted:\s*(\d+).*?sent:\s*(\d+).*?failed:\s*(\d+)', line)
                if attempted_match:
                    packet_info['total_packets'] = int(attempted_match.group(1))
                    packet_info['successful_packets'] = int(attempted_match.group(2))
                    packet_info['failed_packets'] = int(attempted_match.group(3))
                    matched_lines.append(f"尝试/成功/失败: {line}")
                    logger.debug(f"匹配到完整统计: 总计={packet_info['total_packets']}, 成功={packet_info['successful_packets']}, 失败={packet_info['failed_packets']}")
                
                # 格式5: Statistics for eth0: 723 packets (90300 bytes) sent, 59 failed
                stats_match = re.search(r'Statistics.*?(\d+)\s+packets.*?(\d+)\s+failed', line)
                if stats_match:
                    packet_info['total_packets'] = int(stats_match.group(1))
                    packet_info['failed_packets'] = int(stats_match.group(2))
                    packet_info['successful_packets'] = packet_info['total_packets'] - packet_info['failed_packets']
                    matched_lines.append(f"统计信息: {line}")
                    logger.debug(f"匹配到统计信息: 总计={packet_info['total_packets']}, 失败={packet_info['failed_packets']}")
                
                # 格式6: 简单的数字格式 - 大部分tcpreplay版本使用这种格式
                simple_match = re.search(r'^(\d+)\s+packets.*$', line)
                if simple_match and 'Actual' not in line:
                    potential_total = int(simple_match.group(1))
                    if potential_total > packet_info['total_packets']:
                        packet_info['total_packets'] = potential_total
                        matched_lines.append(f"简单格式: {line}")
                        logger.debug(f"匹配到简单格式数据包: {potential_total}")
            
            # 如果没有找到失败数据包，但有总数和成功数，计算失败数
            if packet_info['total_packets'] > 0 and packet_info['successful_packets'] > 0 and packet_info['failed_packets'] == 0:
                packet_info['failed_packets'] = packet_info['total_packets'] - packet_info['successful_packets']
            
            # 如果没有找到成功数据包，但有总数和失败数，计算成功数
            if packet_info['total_packets'] > 0 and packet_info['failed_packets'] > 0 and packet_info['successful_packets'] == 0:
                packet_info['successful_packets'] = packet_info['total_packets'] - packet_info['failed_packets']
            
            # 计算丢包率
            if packet_info['total_packets'] > 0:
                packet_info['packet_loss_rate'] = (
                    packet_info['failed_packets'] / packet_info['total_packets'] * 100
                )
            
            logger.info(f"tcpreplay解析结果: {packet_info}")
            logger.info(f"匹配的行数: {len(matched_lines)}")
            for matched_line in matched_lines:
                logger.debug(f"  - {matched_line}")
                
        except Exception as e:
            logger.error(f"解析tcpreplay输出失败: {e}")
            logger.error(f"输出内容: {output}")
        
        return packet_info
    
    def _parse_suricata_stats(self, suricata_log_content: str) -> Dict[str, Any]:
        """
        解析Suricata日志中的统计信息
        
        Args:
            suricata_log_content: Suricata日志内容
            
        Returns:
            包含Suricata统计信息的字典
        """
        stats_info = {
            'total_packets': 0,
            'dropped_packets': 0,
            'packet_loss_rate': 0.0,
            'alerts_count': 0,
            'rules_loaded': 0,
            'interface': '',
            'invalid_checksum': 0
        }
        
        try:
            import re
            logger.debug(f"开始解析Suricata日志，长度: {len(suricata_log_content)} 字符")
            
            lines = suricata_log_content.split('\n')
            matched_lines = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 解析统计信息行的多种格式
                # 格式1: Stats for 'ens33':  pkts: 723, drop: 59 (8.16%), invalid chksum: 0
                stats_match = re.search(r"Stats for '([^']+)':\s+pkts:\s+(\d+),\s+drop:\s+(\d+)\s+\(([0-9.]+)%\),\s+invalid chksum:\s+(\d+)", line)
                if stats_match:
                    stats_info['interface'] = stats_match.group(1)
                    stats_info['total_packets'] = int(stats_match.group(2))
                    stats_info['dropped_packets'] = int(stats_match.group(3))
                    stats_info['packet_loss_rate'] = float(stats_match.group(4))
                    stats_info['invalid_checksum'] = int(stats_match.group(5))
                    matched_lines.append(f"统计信息: {line}")
                    logger.debug(f"匹配到Suricata统计: 接口={stats_info['interface']}, 总包={stats_info['total_packets']}, 丢包={stats_info['dropped_packets']}, 丢包率={stats_info['packet_loss_rate']}%")
                
                # 格式2: 简化的统计格式 - pkts: 723, drop: 59
                simple_stats_match = re.search(r'pkts:\s*(\d+),?\s*drop:\s*(\d+)', line)
                if simple_stats_match and not stats_match:  # 避免重复匹配
                    stats_info['total_packets'] = int(simple_stats_match.group(1))
                    stats_info['dropped_packets'] = int(simple_stats_match.group(2))
                    if stats_info['total_packets'] > 0:
                        stats_info['packet_loss_rate'] = (stats_info['dropped_packets'] / stats_info['total_packets']) * 100
                    matched_lines.append(f"简化统计: {line}")
                    logger.debug(f"匹配到简化统计: 总包={stats_info['total_packets']}, 丢包={stats_info['dropped_packets']}")
                
                # 解析告警数量的多种格式
                # 格式1: Alerts: 25
                alerts_match = re.search(r'Alerts:\s+(\d+)', line)
                if alerts_match:
                    stats_info['alerts_count'] = int(alerts_match.group(1))
                    matched_lines.append(f"告警数量: {line}")
                    logger.debug(f"匹配到告警数量: {stats_info['alerts_count']}")
                
                # 格式2: XX alerts logged
                alerts_logged_match = re.search(r'(\d+)\s+alerts?\s+logged', line)
                if alerts_logged_match:
                    stats_info['alerts_count'] = int(alerts_logged_match.group(1))
                    matched_lines.append(f"告警记录: {line}")
                    logger.debug(f"匹配到告警记录数: {stats_info['alerts_count']}")
                
                # 解析规则加载信息的多种格式
                # 格式1: 1 rule files processed. 61 rules successfully loaded, 0 rules failed
                rules_match = re.search(r'(\d+)\s+rules? successfully loaded', line)
                if rules_match:
                    stats_info['rules_loaded'] = int(rules_match.group(1))
                    matched_lines.append(f"规则加载: {line}")
                    logger.debug(f"匹配到规则加载数: {stats_info['rules_loaded']}")
                
                # 格式2: Loaded 61 rules
                loaded_match = re.search(r'Loaded\s+(\d+)\s+rules?', line)
                if loaded_match:
                    stats_info['rules_loaded'] = int(loaded_match.group(1))
                    matched_lines.append(f"规则已加载: {line}")
                    logger.debug(f"匹配到已加载规则数: {stats_info['rules_loaded']}")
                
                # 格式3: XX signatures processed
                signatures_match = re.search(r'(\d+)\s+signatures? processed', line)
                if signatures_match:
                    processed_rules = int(signatures_match.group(1))
                    if processed_rules > stats_info['rules_loaded']:  # 取较大值
                        stats_info['rules_loaded'] = processed_rules
                        matched_lines.append(f"签名处理: {line}")
                        logger.debug(f"匹配到处理的签名数: {stats_info['rules_loaded']}")
                
                # 格式4: Rule file loaded with XX rules
                rule_file_match = re.search(r'Rule file.*?with\s+(\d+)\s+rules?', line)
                if rule_file_match:
                    file_rules = int(rule_file_match.group(1))
                    stats_info['rules_loaded'] += file_rules  # 累加
                    matched_lines.append(f"规则文件: {line}")
                    logger.debug(f"累加规则文件规则数: +{file_rules}, 总计={stats_info['rules_loaded']}")
            
            logger.info(f"Suricata解析结果: {stats_info}")
            logger.info(f"匹配的行数: {len(matched_lines)}")
            for matched_line in matched_lines:
                logger.debug(f"  - {matched_line}")
            
            # 如果没有解析到任何数据，记录完整日志内容以便调试
            if all(v == 0 for k, v in stats_info.items() if k not in ['interface']):
                logger.warning("未能从Suricata日志中解析到任何统计信息")
                logger.debug(f"完整Suricata日志内容:\n{suricata_log_content}")
        
        except Exception as e:
            logger.error(f"解析Suricata统计信息失败: {e}")
            logger.error(f"日志内容: {suricata_log_content}")
        
        return stats_info
    
    def _parse_eve_json_stats(self, eve_json_path: str) -> Dict[str, Any]:
        """
        解析eve.json文件获取统计信息
        
        Args:
            eve_json_path: eve.json文件路径
            
        Returns:
            包含统计信息的字典
        """
        stats_info = {
            'total_packets': 0,
            'dropped_packets': 0,
            'packet_loss_rate': 0.0,
            'alerts_count': 0,
            'rules_loaded': 0,
            'interface': ''
        }
        
        try:
            import json
            alert_count = 0
            
            with open(eve_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # 统计alert事件
                        if event.get('event_type') == 'alert':
                            alert_count += 1
                        
                        # 获取统计信息
                        if event.get('event_type') == 'stats':
                            capture_stats = event.get('stats', {}).get('capture', {})
                            decoder_stats = event.get('stats', {}).get('decoder', {})
                            
                            # 从capture统计中获取数据包信息
                            if 'kernel_packets' in capture_stats:
                                stats_info['total_packets'] = capture_stats.get('kernel_packets', 0)
                                stats_info['dropped_packets'] = capture_stats.get('kernel_drops', 0)
                            
                            # 从decoder统计中获取数据包信息
                            if 'pkts' in decoder_stats:
                                stats_info['total_packets'] = max(stats_info['total_packets'], decoder_stats.get('pkts', 0))
                            
                            # 计算丢包率
                            if stats_info['total_packets'] > 0:
                                stats_info['packet_loss_rate'] = (stats_info['dropped_packets'] / stats_info['total_packets']) * 100
                    
                    except json.JSONDecodeError:
                        continue
            
            stats_info['alerts_count'] = alert_count
            logger.debug(f"从eve.json解析到: {stats_info}")
            
        except Exception as e:
            logger.warning(f"解析eve.json失败: {e}")
        
        return stats_info
    
    def _parse_stats_log(self, stats_content: str) -> Dict[str, Any]:
        """
        解析stats.log文件获取统计信息
        
        Args:
            stats_content: stats.log文件内容
            
        Returns:
            包含统计信息的字典
        """
        stats_info = {
            'total_packets': 0,
            'dropped_packets': 0,
            'packet_loss_rate': 0.0,
            'alerts_count': 0,
            'rules_loaded': 0,
            'interface': ''
        }
        
        try:
            import re
            lines = stats_content.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 解析捕获统计: Capture.Kernel_packets = 723
                kernel_packets_match = re.search(r'Capture\.Kernel_packets\s*=\s*(\d+)', line)
                if kernel_packets_match:
                    stats_info['total_packets'] = int(kernel_packets_match.group(1))
                
                # 解析丢包统计: Capture.Kernel_drops = 59
                kernel_drops_match = re.search(r'Capture\.Kernel_drops\s*=\s*(\d+)', line)
                if kernel_drops_match:
                    stats_info['dropped_packets'] = int(kernel_drops_match.group(1))
                
                # 解析decoder包统计: Decoder.Pkts = 723
                decoder_pkts_match = re.search(r'Decoder\.Pkts\s*=\s*(\d+)', line)
                if decoder_pkts_match:
                    decoder_pkts = int(decoder_pkts_match.group(1))
                    stats_info['total_packets'] = max(stats_info['total_packets'], decoder_pkts)
                
                # 解析告警统计: Detect.Alert = 25
                alert_match = re.search(r'Detect\.Alert\s*=\s*(\d+)', line)
                if alert_match:
                    stats_info['alerts_count'] = int(alert_match.group(1))
            
            # 计算丢包率
            if stats_info['total_packets'] > 0:
                stats_info['packet_loss_rate'] = (stats_info['dropped_packets'] / stats_info['total_packets']) * 100
            
            logger.debug(f"从stats.log解析到: {stats_info}")
            
        except Exception as e:
            logger.warning(f"解析stats.log失败: {e}")
        
        return stats_info
    
    def _analyze_packet_loss(self, packet_loss_rate: float) -> Dict[str, str]:
        """
        分析丢包率并提供建议
        
        Args:
            packet_loss_rate: 丢包率（百分比）
            
        Returns:
            包含分析结果和建议的字典
        """
        if packet_loss_rate < 1.0:
            level = "正常"
            color = "green"
            suggestion = "丢包率正常，分析质量良好"
        elif packet_loss_rate < 3.0:
            level = "良好"
            color = "blue"
            suggestion = "丢包率较低，分析质量较好"
        elif packet_loss_rate < 5.0:
            level = "一般"
            color = "orange"
            suggestion = "丢包率偏高，建议检查网络负载或调整分析参数"
        elif packet_loss_rate < 10.0:
            level = "较高"
            color = "red"
            suggestion = "丢包率较高，可能影响分析准确性，建议:\n• 降低tcpreplay发送速度\n• 检查系统负载\n• 优化Suricata配置"
        else:
            level = "很高"
            color = "darkred"
            suggestion = "丢包率很高，严重影响分析质量，建议:\n• 大幅降低tcpreplay发送速度(--mbps=10)\n• 检查系统资源\n• 升级硬件配置\n• 分批分析大文件"
        
        return {
            'level': level,
            'color': color,
            'suggestion': suggestion
        }
    
    def _process_analysis_results(self, output_dir: str, packet_info: Dict[str, Any], analysis_mode: str) -> bool:
        """
        处理分析结果
        
        Args:
            output_dir: 输出目录
            packet_info: 数据包信息（来自tcpreplay）
            analysis_mode: 分析模式
            
        Returns:
            是否成功
        """
        try:
            fast_log_path = os.path.join(output_dir, "fast.log")
            suricata_log_path = os.path.join(output_dir, "suricata.log")
            
            if os.path.exists(fast_log_path):
                # 解析告警
                self.alerts = self.alert_parser.parse_fast_log(fast_log_path)
                
                # 尝试解析Suricata日志获取更准确的统计信息
                suricata_stats = {}
                if os.path.exists(suricata_log_path):
                    try:
                        with open(suricata_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            suricata_log_content = f.read()
                        suricata_stats = self._parse_suricata_stats(suricata_log_content)
                        logger.info(f"成功解析Suricata统计信息: {suricata_stats}")
                    except Exception as e:
                        logger.warning(f"读取Suricata日志失败: {e}")
                else:
                    logger.warning(f"Suricata日志文件不存在: {suricata_log_path}")
                
                # 尝试从eve.json获取额外信息
                eve_json_path = os.path.join(output_dir, "eve.json")
                eve_stats = {}
                if os.path.exists(eve_json_path):
                    try:
                        eve_stats = self._parse_eve_json_stats(eve_json_path)
                        logger.info(f"从eve.json解析到额外统计: {eve_stats}")
                    except Exception as e:
                        logger.warning(f"解析eve.json失败: {e}")
                
                # 尝试从stats.log获取信息
                stats_log_path = os.path.join(output_dir, "stats.log")
                stats_log_info = {}
                if os.path.exists(stats_log_path):
                    try:
                        with open(stats_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            stats_content = f.read()
                        stats_log_info = self._parse_stats_log(stats_content)
                        logger.info(f"从stats.log解析到统计: {stats_log_info}")
                    except Exception as e:
                        logger.warning(f"解析stats.log失败: {e}")
                
                # 合并统计信息，优先级：Suricata主日志 > stats.log > eve.json > tcpreplay
                final_stats = {
                    'packet_loss_rate': 0.0,
                    'total_packets': 0,
                    'dropped_packets': 0,
                    'interface': 'unknown',
                    'rules_loaded': 0,
                    'data_source': 'unknown'
                }
                
                # 优先使用Suricata主日志的统计信息
                if suricata_stats.get('total_packets', 0) > 0:
                    final_stats.update({
                        'packet_loss_rate': suricata_stats['packet_loss_rate'],
                        'total_packets': suricata_stats['total_packets'],
                        'dropped_packets': suricata_stats['dropped_packets'],
                        'interface': suricata_stats.get('interface', 'unknown'),
                        'rules_loaded': suricata_stats.get('rules_loaded', 0),
                        'data_source': "Suricata主日志"
                    })
                # 其次使用stats.log的信息
                elif stats_log_info.get('total_packets', 0) > 0:
                    final_stats.update({
                        'packet_loss_rate': stats_log_info.get('packet_loss_rate', 0.0),
                        'total_packets': stats_log_info['total_packets'],
                        'dropped_packets': stats_log_info.get('dropped_packets', 0),
                        'interface': stats_log_info.get('interface', 'unknown'),
                        'rules_loaded': stats_log_info.get('rules_loaded', 0),
                        'data_source': "stats.log"
                    })
                # 再次使用eve.json的信息
                elif eve_stats.get('total_packets', 0) > 0:
                    final_stats.update({
                        'packet_loss_rate': eve_stats.get('packet_loss_rate', 0.0),
                        'total_packets': eve_stats['total_packets'],
                        'dropped_packets': eve_stats.get('dropped_packets', 0),
                        'interface': eve_stats.get('interface', 'unknown'),
                        'rules_loaded': eve_stats.get('rules_loaded', 0),
                        'data_source': "eve.json"
                    })
                # 最后使用tcpreplay的统计信息
                elif packet_info['total_packets'] > 0:
                    final_stats.update({
                        'packet_loss_rate': packet_info['packet_loss_rate'],
                        'total_packets': packet_info['total_packets'],
                        'dropped_packets': packet_info['failed_packets'],
                        'interface': "tcpreplay",
                        'rules_loaded': 0,
                        'data_source': "tcpreplay统计"
                    })
                
                # 确保规则加载数不为0，从任何可用源获取
                if final_stats['rules_loaded'] == 0:
                    for source in [suricata_stats, stats_log_info, eve_stats]:
                        if source.get('rules_loaded', 0) > 0:
                            final_stats['rules_loaded'] = source['rules_loaded']
                            break
                
                # 从最终统计中提取数据
                final_packet_loss = final_stats['packet_loss_rate']
                total_packets = final_stats['total_packets']
                dropped_packets = final_stats['dropped_packets']
                interface = final_stats['interface']
                rules_loaded = final_stats['rules_loaded']
                data_source = final_stats['data_source']
                
                logger.info(f"最终统计结果: {final_stats}")
                
                # 分析丢包率并获取建议
                loss_analysis = self._analyze_packet_loss(final_packet_loss)
                
                # 在主线程中更新UI
                self.root.after(0, self.refresh_alerts_list)
                
                # 构建详细的结果信息并记录到日志
                result_msg = f"""📊 数据包分析完成 [{analysis_mode.upper()}模式]

🔍 统计信息 ({data_source}):
• 网络接口: {interface}
• 总数据包: {total_packets:,}
• 丢弃数据包: {dropped_packets:,}
• 丢包率: {final_packet_loss:.2f}% ({loss_analysis['level']})

📋 检测结果:
• 加载规则: {rules_loaded} 条
• 检测告警: {len(self.alerts)} 个

💡 丢包率分析:
{loss_analysis['suggestion']}"""
                
                logger.info(result_msg)
                
                # 根据丢包率水平设置不同的状态信息
                if final_packet_loss < 5.0:
                    status_msg = f"{analysis_mode}模式分析完成，发现 {len(self.alerts)} 个告警，丢包率 {final_packet_loss:.2f}% (正常)"
                else:
                    status_msg = f"{analysis_mode}模式分析完成，发现 {len(self.alerts)} 个告警，丢包率 {final_packet_loss:.2f}% (需关注)"
                
                self.root.after(0, lambda: self.alert_status_var.set(status_msg))
                
                # 如果丢包率过高，记录警告
                if final_packet_loss >= 5.0:
                    logger.warning(f"丢包率较高: {final_packet_loss:.2f}%，{loss_analysis['suggestion']}")
                
                # 告警模块完成后，自动加载全量日志
                self.root.after(0, self.auto_load_eve_log)
                
                return True
            else:
                self.root.after(0, lambda: self.alert_status_var.set("未找到分析结果文件"))
                return False
                
        except Exception as e:
            logger.error(f"处理分析结果失败: {e}")
            return False

    def _try_remote_new_analysis(self, pcap_file: str, analysis_mode: str, network_interface: str, replay_speed: str) -> bool:
        """
        尝试远程新方法分析
        
        Args:
            pcap_file: 数据包文件路径
            analysis_mode: 分析模式
            network_interface: 网络接口
            replay_speed: tcpreplay发送速度(Mbps)
            
        Returns:
            是否成功
        """
        try:
            # 检查是否有远程连接配置
            if not REMOTE_CONNECT_AVAILABLE:
                return False
            
            self.root.after(0, lambda: self.alert_status_var.set("正在连接远程服务器..."))
            
            # 尝试加载上次配置
            config_manager = ConfigManager()
            last_config = config_manager.load_config()
            
            if not last_config:
                return False
            
            config = {
                "host": last_config.get('host'),
                "port": last_config.get('port', 22),
                "username": last_config.get('username'),
                "password": last_config.get('password')
            }
            
            # 创建连接对象
            server = RemoteServer(
                host=config['host'],
                port=config['port'],
                username=config['username'],
                password=config['password']
            )
            
            # 建立连接（带重试机制）
            self.root.after(0, lambda: self.alert_status_var.set("正在建立SSH连接..."))
            
            if not server.connect(max_retries=3, retry_delay=2.0):
                self.root.after(0, lambda: self.alert_status_var.set("SSH连接失败"))
                return False
            
            try:
                # 上传数据包文件
                self.root.after(0, lambda: self.alert_status_var.set("正在上传数据包文件..."))
                
                remote_pcap_path = f"/tmp/{os.path.basename(pcap_file)}"
                if not server.upload_file(pcap_file, remote_pcap_path):
                    return False
                
                # 创建远程输出目录
                remote_output_dir = f"/tmp/suricata_output_{int(time.time())}"
                server.execute_command(f"mkdir -p {remote_output_dir}")
                
                self.root.after(0, lambda: self.alert_status_var.set(f"正在运行远程{analysis_mode}模式分析..."))
                
                # 构建远程suricata命令
                # 使用时间戳确保每次运行都有唯一的日志文件
                #timestamp = int(time.time())
                suricata_cmd = f"nohup suricata -i {network_interface} -c /etc/suricata/suricata.yaml -v -k none --runmode {analysis_mode} -l {remote_output_dir} > /tmp/suricata.log 2>&1 &"
                
                # 启动远程suricata
                server.execute_command(suricata_cmd)
                
                # 等待suricata启动
                time.sleep(5)
                
                # 运行tcpreplay
                tcpreplay_cmd = f"tcpreplay --mbps={replay_speed} -i {network_interface} {remote_pcap_path}"
                success, tcpreplay_output, tcpreplay_error = server.execute_command(tcpreplay_cmd)
                
                # 等待suricata处理完成
                time.sleep(10)
                
                # 停止suricata
                server.execute_command("pkill -f suricata")
                
                # 解析tcpreplay输出
                packet_loss_info = self._parse_tcpreplay_output(tcpreplay_error)
                
                # 下载分析结果
                self.root.after(0, lambda: self.alert_status_var.set("正在下载分析结果..."))
                
                local_output_dir = os.path.join(self.current_pcap_dir, "suricata_output")
                os.makedirs(local_output_dir, exist_ok=True)
                
                # 定义要下载的日志文件列表
                log_files_to_download = [
                    ("fast.log", "告警日志"),
                    ("eve.json", "JSON事件日志"),
                    ("stats.log", "统计日志")
                ]
                
                download_success = True
                downloaded_files = []
                
                for log_file, description in log_files_to_download:
                    remote_log_path = f"{remote_output_dir}/{log_file}"
                    local_log_path = os.path.join(local_output_dir, log_file)
                    
                    logger.info(f"尝试下载{description}: {remote_log_path}")
                    
                    if server.download_file(remote_log_path, local_log_path):
                        downloaded_files.append((log_file, description, local_log_path))
                        logger.info(f"✅ 成功下载{description}: {log_file}")
                    else:
                        logger.warning(f"⚠️ 下载{description}失败: {log_file}")
                        # 只有fast.log是必需的，其他文件下载失败不影响整体流程
                        if log_file == "fast.log":
                            download_success = False
                
                # 输出下载结果到系统日志
                download_summary = f"📥 远程日志文件下载完成:\n"
                download_summary += f"• 成功下载: {len(downloaded_files)} 个文件\n"
                for log_file, description, local_path in downloaded_files:
                    file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
                    download_summary += f"  - {description}({log_file}): {file_size:,} 字节\n"
                
                logger.info(download_summary)
                
                # suricata.log不再下载到本地，只保留在远程suricata_out_目录中
                
                if download_success:
                    # 处理分析结果
                    return self._process_analysis_results(local_output_dir, packet_loss_info, analysis_mode)
                else:
                    self.root.after(0, lambda: self.alert_status_var.set("下载关键日志文件失败"))
                    return False
                    
            finally:
                # 清理远程文件
                #server.execute_command(f"rm -rf {remote_pcap_path} {remote_output_dir}")
                server.disconnect()
                
        except Exception as e:
            logger.error(f"远程新方法分析失败: {str(e)}")
            return False

    def _validate_rules_syntax(self) -> List[Dict[str, Any]]:
        """
        验证规则语法
        
        Returns:
            语法错误列表
        """
        errors = []
        
        for line_num, line in enumerate(self.rules_content, 1):
            line = line.strip()
            
            # 跳过空行和注释行
            if not line or line.startswith('#'):
                continue
            
            # 检查基本的Suricata规则语法
            try:
                # 检查规则是否以分号结尾
                if not line.endswith(';'):
                    errors.append({
                        'line': line_num,
                        'message': '规则必须以分号结尾',
                        'rule': line
                    })
                    continue
                
                # 检查规则是否包含基本组件
                if not any(keyword in line.lower() for keyword in ['alert', 'drop', 'reject', 'pass']):
                    errors.append({
                        'line': line_num,
                        'message': '规则必须包含动作关键字 (alert/drop/reject/pass)',
                        'rule': line
                    })
                    continue
                
                # 检查引号匹配
                quote_count = line.count('"')
                if quote_count % 2 != 0:
                    errors.append({
                        'line': line_num,
                        'message': '引号不匹配',
                        'rule': line
                    })
                
                # 检查括号匹配
                open_parens = line.count('(')
                close_parens = line.count(')')
                if open_parens != close_parens:
                    errors.append({
                        'line': line_num,
                        'message': '括号不匹配',
                        'rule': line
                    })
                
                # 检查常见的语法错误
                if 'msg:' in line and not re.search(r'msg:\s*"[^"]*"', line):
                    errors.append({
                        'line': line_num,
                        'message': 'msg字段格式错误，应为 msg:"消息内容"',
                        'rule': line
                    })
                
                if 'sid:' in line and not re.search(r'sid:\s*\d+', line):
                    errors.append({
                        'line': line_num,
                        'message': 'sid字段格式错误，应为 sid:数字',
                        'rule': line
                    })
                
                # 检查常见的拼写错误（基于用户提供的错误日志）
                if 'MSg:' in line:  # 应该是 msg:
                    errors.append({
                        'line': line_num,
                        'message': 'MSg: 应该是 msg:',
                        'rule': line
                    })
                
                if 'flowbits:' in line and not line.endswith(';'):
                    errors.append({
                        'line': line_num,
                        'message': 'flowbits规则缺少结尾分号',
                        'rule': line
                    })
                
            except Exception as e:
                errors.append({
                    'line': line_num,
                    'message': f'解析错误: {str(e)}',
                    'rule': line
                })
        
        return errors

    def analyze_pcap_with_suricata(self, pcap_file: str):
        """
        使用Suricata分析数据包
        
        Args:
            pcap_file: 数据包文件路径
        """
        try:
            # 首先尝试本地分析
            if self.try_local_analysis(pcap_file):
                return
            
            # 如果本地分析失败，尝试远程分析
            if REMOTE_CONNECT_AVAILABLE:
                if self.try_remote_analysis(pcap_file):
                    return
            
            # 如果都失败了，显示错误信息
            messagebox.showerror("错误", "无法进行数据包分析。\n\n可能的原因：\n1. Suricata未安装或不在PATH中\n2. 远程服务器连接失败\n3. 数据包文件格式不支持")
            self.alert_status_var.set("分析失败")
            
        except Exception as e:
            messagebox.showerror("错误", f"分析失败: {str(e)}")
            self.alert_status_var.set("分析失败")

    def try_local_analysis(self, pcap_file: str) -> bool:
        """
        尝试本地分析数据包
        
        Args:
            pcap_file: 数据包文件路径
            
        Returns:
            bool: 是否成功
        """
        try:
            # 检查suricata是否可用
            result = subprocess.run(['suricata', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return False
            
            # 创建带时间戳的输出目录，避免多次分析时的文件冲突
            timestamp = int(time.time())
            output_dir = os.path.join(self.current_pcap_dir, f"suricata_output_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            
            # 运行suricata分析
            cmd = [
                'suricata',
                '-r', pcap_file,
                '-l', output_dir,
                '--init-errors-fatal'
            ]
            
            self.alert_status_var.set("正在运行本地Suricata分析...")
            self.root.update()
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # 输出本地分析的日志文件信息到系统日志
                local_log_files = ["fast.log", "suricata.log", "eve.json", "stats.log"]
                available_files = []
                
                for log_file in local_log_files:
                    log_path = os.path.join(output_dir, log_file)
                    if os.path.exists(log_path):
                        file_size = os.path.getsize(log_path)
                        available_files.append((log_file, file_size))
                        logger.info(f"✅ 本地生成{log_file}: {file_size:,} 字节")
                
                # 输出本地文件汇总到系统日志
                local_summary = f"📁 本地Suricata分析文件生成完成:\n"
                local_summary += f"• 生成文件: {len(available_files)} 个\n"
                for log_file, file_size in available_files:
                    local_summary += f"  - {log_file}: {file_size:,} 字节\n"
                
                logger.info(local_summary)
                
                # suricata.log已生成，可用于后续分析（不在系统日志中输出解析结果）
                
                # 解析告警文件
                fast_log = os.path.join(output_dir, "fast.log")
                if os.path.exists(fast_log):
                    self.alerts = self.alert_parser.parse_fast_log(fast_log)
                    self.refresh_alerts_list()
                    self.alert_status_var.set(f"本地分析完成，发现 {len(self.alerts)} 个告警")
                    return True
                else:
                    self.alert_status_var.set("本地分析完成，未发现告警")
                    return True
            
            return False
                
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
        except Exception as e:
            logger.error(f"本地分析失败: {str(e)}")
            return False

    def try_remote_analysis(self, pcap_file: str) -> bool:
        """
        尝试远程分析数据包
        
        Args:
            pcap_file: 数据包文件路径
            
        Returns:
            bool: 是否成功
        """
        try:
            # 检查是否有远程连接配置
            if not REMOTE_CONNECT_AVAILABLE:
                return False
            
            # 尝试加载上次配置
            config_manager = ConfigManager()
            last_config = config_manager.load_config()
            
            if not last_config:
                # 如果没有配置，显示配置对话框
                config_dialog = ServerConfigDialog(self.root)
                if not config_dialog.result:
                    return False
                config = config_dialog.result
            else:
                # 使用上次配置
                config = {
                    "host": last_config.get('host'),
                    "port": last_config.get('port', 22),
                    "username": last_config.get('username'),
                    "password": last_config.get('password'),
                    "remote_path": "/tmp",
                    "auth_method": "password",
                    "key_path": ""
                }
            
            # 开始远程分析流程
            self.alert_status_var.set("正在连接服务器...")
            self.root.update()
            
            # 创建连接对象
            server = RemoteServer(
                host=config['host'],
                port=config['port'],
                username=config['username'],
                password=config['password']
            )
            
            # 建立连接（带重试机制）
            self.alert_status_var.set("正在建立SSH连接...")
            self.root.update()
            
            if not server.connect(max_retries=3, retry_delay=2.0):
                error_msg = f"""无法连接到服务器 {config['host']}:{config['port']}

请检查：
1. 服务器是否在线
2. SSH服务是否运行
3. 网络连接是否正常
4. 防火墙设置"""
                messagebox.showerror("连接失败", error_msg)
                self.alert_status_var.set("连接失败")
                return False
            
            try:
                # 上传数据包文件
                self.alert_status_var.set("正在上传数据包文件...")
                self.root.update()
                
                remote_pcap_path = f"/tmp/{os.path.basename(pcap_file)}"
                if not server.upload_file(pcap_file, remote_pcap_path):
                    messagebox.showerror("错误", "数据包文件上传失败")
                    return False
                
                # 创建远程输出目录
                remote_output_dir = f"/tmp/suricata_output_{int(time.time())}"
                server.execute_command(f"mkdir -p {remote_output_dir}")
                
                # 运行远程suricata分析
                self.alert_status_var.set("正在运行远程Suricata分析...")
                self.root.update()
                
                analysis_cmd = f"suricata -r {remote_pcap_path} -l {remote_output_dir} --init-errors-fatal"
                success, output, error = server.execute_command(analysis_cmd)
                
                if not success:
                    messagebox.showerror("错误", f"远程Suricata分析失败: {error}")
                    return False
                
                # 下载分析结果文件
                self.alert_status_var.set("正在下载分析结果...")
                self.root.update()
                
                local_output_dir = os.path.join(self.current_pcap_dir, "suricata_output")
                os.makedirs(local_output_dir, exist_ok=True)
                
                # 定义要下载的日志文件列表
                log_files_to_download = [
                    ("fast.log", "告警日志"),
                    ("eve.json", "JSON事件日志"),
                    ("stats.log", "统计日志")
                ]
                
                download_success = True
                downloaded_files = []
                
                for log_file, description in log_files_to_download:
                    remote_log_path = f"{remote_output_dir}/{log_file}"
                    local_log_path = os.path.join(local_output_dir, log_file)
                    
                    logger.info(f"尝试下载{description}: {log_file}")
                    
                    if server.download_file(remote_log_path, local_log_path):
                        downloaded_files.append((log_file, description, local_log_path))
                        logger.info(f"✅ 成功下载{description}: {log_file}")
                    else:
                        logger.warning(f"⚠️ 下载{description}失败: {log_file}")
                        # 只有fast.log是必需的，其他文件下载失败不影响整体流程
                        if log_file == "fast.log":
                            download_success = False
                
                # 输出下载结果到系统日志
                download_summary = f"📥 远程日志文件下载完成:\n"
                download_summary += f"• 成功下载: {len(downloaded_files)} 个文件\n"
                for log_file, description, local_path in downloaded_files:
                    file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
                    download_summary += f"  - {description}({log_file}): {file_size:,} 字节\n"
                
                logger.info(download_summary)
                
                # suricata.log不再下载到本地，只保留在远程suricata_out_目录中
                
                if download_success:
                    # 解析告警文件
                    local_fast_log = os.path.join(local_output_dir, "fast.log")
                    if os.path.exists(local_fast_log):
                        self.alerts = self.alert_parser.parse_fast_log(local_fast_log)
                        self.refresh_alerts_list()
                        self.alert_status_var.set(f"远程分析完成，发现 {len(self.alerts)} 个告警")
                        
                        # 不清理远程文件，保留供后续使用
                        #server.execute_command(f"rm -rf {remote_pcap_path} {remote_output_dir}")
                        return True
                    else:
                        self.alert_status_var.set("远程分析完成，未发现告警")
                        return True
                else:
                    messagebox.showerror("错误", "无法下载关键分析结果文件")
                    return False
                
            finally:
                # 断开连接
                server.disconnect()
                
        except Exception as e:
            logger.error(f"远程分析失败: {str(e)}")
            messagebox.showerror("错误", f"远程分析失败: {str(e)}")
            return False

    def refresh_alerts(self):
        """
        刷新告警列表
        """
        if not self.current_pcap_dir:
            messagebox.showwarning("警告", "请先选择数据包文件")
            return
        
        output_dir = os.path.join(self.current_pcap_dir, "suricata_output")
        fast_log = os.path.join(output_dir, "fast.log")
        
        if os.path.exists(fast_log):
            self.alerts = self.alert_parser.parse_fast_log(fast_log)
            self.refresh_alerts_list()
            self.alert_status_var.set(f"已刷新，共 {len(self.alerts)} 个告警")
        else:
            messagebox.showwarning("警告", "未找到告警文件，请先运行分析")
            self.alert_status_var.set("未找到告警文件")

    def clear_alerts(self):
        """
        清空告警列表
        """
        self.alerts.clear()
        self.refresh_alerts_list()
        self.alert_status_var.set("告警列表已清空")

    def refresh_alerts_list(self):
        """
        刷新告警列表显示
        """
        # 清空现有项目
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # 获取搜索和过滤条件
        search_text = self.alert_search_var.get().lower()
        priority_filter = self.priority_filter.get()
        protocol_filter = self.protocol_filter.get()
        merge_enabled = self.merge_alerts_var.get()
        
        # 首先过滤告警
        filtered_alerts = []
        for alert in self.alerts:
            # 应用优先级过滤
            if priority_filter != "全部" and str(alert.get('priority', '')) != priority_filter:
                continue
            
            # 应用协议过滤
            if protocol_filter != "全部" and protocol_filter not in alert.get('protocol', '').upper():
                continue
            
            # 应用搜索过滤
            if search_text:
                if not self.matches_alert_search(alert, search_text):
                    continue
            
            filtered_alerts.append(alert)
        
        # 处理告警（合并或直接显示）
        if merge_enabled:
            # 合并相同告警
            merged_alerts = self.merge_alerts(filtered_alerts)
            display_alerts = merged_alerts
        else:
            # 不合并，直接显示
            display_alerts = [{'alert': alert, 'count': 1} for alert in filtered_alerts]
        
        # 显示告警
        for merged_alert in display_alerts:
            alert = merged_alert['alert']
            count = merged_alert['count']
            
            # 显示告警
            alert_message = UIHelper.truncate_text(
                alert.get('message', ''), 
                AppConfig.ALERT_MAX_DISPLAY_LENGTH
            )
            self.alerts_tree.insert("", "end", values=(
                alert_message,
                alert.get('priority', ''),
                alert.get('protocol', ''),
                alert.get('src_ip', ''),
                alert.get('src_port', ''),
                alert.get('dst_ip', ''),
                alert.get('dst_port', ''),
                alert.get('sid', ''),
                count
            ))
        
        # 更新状态栏
        total_alerts = sum(item['count'] for item in display_alerts)
        unique_alerts = len(display_alerts)
        
        if search_text or priority_filter != "全部" or protocol_filter != "全部":
            if merge_enabled:
                self.alert_status_var.set(f"显示 {unique_alerts} 种告警，共 {total_alerts} 次 (已过滤)")
            else:
                self.alert_status_var.set(f"显示 {total_alerts} 个告警 (已过滤)")
        else:
            if merge_enabled:
                self.alert_status_var.set(f"显示 {unique_alerts} 种告警，共 {len(self.alerts)} 次")
            else:
                self.alert_status_var.set(f"显示 {len(self.alerts)} 个告警")

    def merge_alerts(self, alerts: List[dict]) -> List[dict]:
        """
        合并相同的告警
        
        Args:
            alerts: 告警列表
            
        Returns:
            List[dict]: 合并后的告警列表，每项包含alert和count
        """
        merged = {}
        
        for alert in alerts:
            # 定义合并键（相同SID、源IP、目标IP、协议认为是相同告警）
            merge_key = (
                alert.get('sid', ''),
                alert.get('src_ip', ''),
                alert.get('dst_ip', ''),
                alert.get('protocol', ''),
                alert.get('message', '')  # 添加消息也作为合并键的一部分
            )
            
            if merge_key in merged:
                # 增加计数
                merged[merge_key]['count'] += 1
                # 可以选择更新其他信息，比如最新的时间戳
                if alert.get('timestamp'):
                    merged[merge_key]['alert']['latest_timestamp'] = alert.get('timestamp')
            else:
                # 新的告警类型
                merged[merge_key] = {
                    'alert': alert.copy(),
                    'count': 1
                }
                # 保存第一次出现的时间戳
                if alert.get('timestamp'):
                    merged[merge_key]['alert']['first_timestamp'] = alert.get('timestamp')
                    merged[merge_key]['alert']['latest_timestamp'] = alert.get('timestamp')
        
        # 按出现次数排序（次数多的在前）
        result = list(merged.values())
        result.sort(key=lambda x: x['count'], reverse=True)
        
        return result

    def matches_alert_search(self, alert: dict, search_text: str) -> bool:
        """
        检查告警是否匹配搜索条件
        
        Args:
            alert: 告警信息
            search_text: 搜索文本
            
        Returns:
            bool: 是否匹配
        """
        if not search_text:
            return True
        
        search_text = search_text.lower()
        
        # 搜索告警消息、IP地址、端口等
        searchable_fields = [
            alert.get('message', ''),
            alert.get('src_ip', ''),
            alert.get('dst_ip', ''),
            str(alert.get('src_port', '')),
            str(alert.get('dst_port', '')),
            alert.get('protocol', ''),
            alert.get('classification', '')
        ]
        
        return any(search_text in field.lower() for field in searchable_fields)

    def on_alert_search_change(self, event=None):
        """
        告警搜索条件改变时的处理
        """
        self.refresh_alerts_list()

    def clear_alert_search(self):
        """
        清除告警搜索条件
        """
        self.alert_search_var.set("")
        self.priority_filter.set("全部")
        self.protocol_filter.set("全部")
        self.refresh_alerts_list()
        self.alert_status_var.set("搜索已清除")

    def on_alert_double_click(self, event):
        """
        双击告警事件处理
        """
        selected_items = self.alerts_tree.selection()
        if not selected_items:
            return
        
        # 获取选中的告警
        item = selected_items[0]
        values = self.alerts_tree.item(item)['values']
        
        # 显示告警详情
        self.show_alert_details(values)

    def show_alert_details(self, alert_values):
        """
        显示告警详情
        
        Args:
            alert_values: 告警值列表
        """
        if not alert_values:
            return
        
        # 创建详情对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("告警详情")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 居中显示
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 100))
        
        # 创建详情内容
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 告警信息
        details_text = scrolledtext.ScrolledText(main_frame, height=20, width=70)
        details_text.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        
        # 格式化告警信息（适应新的列结构）
        details = f"""告警详情:
        
告警信息: {alert_values[0]}
优先级: {alert_values[1]}
协议: {alert_values[2]}
源IP: {alert_values[3]}
源端口: {alert_values[4]}
目标IP: {alert_values[5]}
目标端口: {alert_values[6]}
SID: {alert_values[7]}
出现次数: {alert_values[8]}
"""
        
        details_text.insert(tk.END, details)
        details_text.config(state=tk.DISABLED)
        
        # 关闭按钮
        ttk.Button(main_frame, text="关闭", command=dialog.destroy).pack()
    
    def refresh_log(self) -> None:
        """刷新日志显示"""
        try:
            if not os.path.exists(self.log_file_path):
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, "日志文件不存在\n")
                self.log_status_var.set("日志文件不存在")
                return
            
            # 获取显示行数
            max_lines = int(self.log_lines_var.get())
            
            # 读取日志文件的最后N行
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # 是否仅显示重点日志
            focus_only = getattr(self, 'focus_only_var', None)
            focus_enabled = bool(focus_only.get()) if focus_only else False
            if focus_enabled:
                # 重点日志：仅 INFO 类日志；并额外包含最新一次的摘要段落
                focus_levels = [" - INFO - "]
                filtered_lines = [ln for ln in lines if any(level in ln for level in focus_levels)]

                # 额外包含最近一次的分析摘要关键段落标题及其内容（直到空行）：
                # 1) 统计信息 (...):  2) 📋 检测结果:  3) 💡 丢包率分析:
                try:
                    last_stat_idx = -1
                    last_detect_idx = -1
                    last_loss_idx = -1
                    for idx in range(len(lines) - 1, -1, -1):
                        text = lines[idx]
                        if last_stat_idx == -1 and ("统计信息 (" in text and "):" in text):
                            last_stat_idx = idx
                        if last_detect_idx == -1 and "检测结果:" in text:
                            last_detect_idx = idx
                        if last_loss_idx == -1 and "丢包率分析:" in text:
                            last_loss_idx = idx
                        if last_stat_idx != -1 and last_detect_idx != -1 and last_loss_idx != -1:
                            break

                    def append_block(start_index: int) -> None:
                        if start_index is None or start_index < 0 or start_index >= len(lines):
                            return
                        j = start_index
                        while j < len(lines) and lines[j].strip() != "":
                            ln = lines[j]
                            if ln not in filtered_lines:
                                filtered_lines.append(ln)
                            j += 1

                    append_block(last_stat_idx)
                    append_block(last_detect_idx)
                    append_block(last_loss_idx)
                except Exception:
                    pass
                total_focus = len(filtered_lines)
                source_lines = filtered_lines
            else:
                total_focus = len(lines)
                source_lines = lines
                
            # 只显示最后的指定行数
            if len(source_lines) > max_lines:
                display_lines = source_lines[-max_lines:]
                if focus_enabled:
                    header = f"... (仅重点(INFO)+摘要) 显示最后 {max_lines} 行，共 {total_focus}/{len(lines)} 行 ...\n\n"
                else:
                    header = f"... (显示最后 {max_lines} 行，共 {len(lines)} 行) ...\n\n"
            else:
                display_lines = source_lines
                if focus_enabled:
                    header = f"(仅重点(INFO)+摘要，共 {total_focus}/{len(lines)} 行)\n\n"
                else:
                    header = f"(共 {len(lines)} 行)\n\n"
            
            if focus_enabled and not display_lines:
                # 无重点日志，给出提示
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, header)
                self.log_text.insert(tk.END, "暂无重点日志\n")
                current_time = datetime.now().strftime("%H:%M:%S")
                self.log_status_var.set(f"最后更新: {current_time} | 显示: 0/{len(lines)} 行 (仅重点(INFO)+摘要)")
                return
            
            # 如果开启重点模式且过滤后为空，但原日志非空，上面的强制包含最后一条已确保至少有1条
            
            # 更新日志显示
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, header)
            
            # 添加日志内容，并根据日志级别进行颜色标记
            for line in display_lines:
                line_start = self.log_text.index(tk.INSERT)
                self.log_text.insert(tk.END, line)
                line_end = self.log_text.index(tk.INSERT)
                
                # 根据日志级别设置颜色
                if " - ERROR - " in line or " - CRITICAL - " in line:
                    self.log_text.tag_add("error", line_start, line_end)
                    self.log_text.tag_config("error", foreground="red")
                elif " - WARNING - " in line:
                    self.log_text.tag_add("warning", line_start, line_end)
                    self.log_text.tag_config("warning", foreground="orange")
                elif " - INFO - " in line:
                    self.log_text.tag_add("info", line_start, line_end)
                    self.log_text.tag_config("info", foreground="blue")
                elif " - DEBUG - " in line:
                    self.log_text.tag_add("debug", line_start, line_end)
                    self.log_text.tag_config("debug", foreground="gray")
            
            # 滚动到底部
            self.log_text.see(tk.END)
            
            # 更新状态
            current_time = datetime.now().strftime("%H:%M:%S")
            if focus_enabled:
                self.log_status_var.set(f"最后更新: {current_time} | 显示: {len(display_lines)}/{len(lines)} 行 (仅重点(INFO)+摘要)")
            else:
                self.log_status_var.set(f"最后更新: {current_time} | 显示: {len(display_lines)}/{len(lines)} 行")
            
        except Exception as e:
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, f"读取日志文件失败: {str(e)}\n")
            self.log_status_var.set(f"读取失败: {str(e)}")
            logger.error(f"刷新日志失败: {str(e)}")
    
    def clear_log_display(self) -> None:
        """清空日志显示"""
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, "日志显示已清空\n")
        self.log_status_var.set("日志显示已清空")
    
    def start_log_monitoring(self) -> None:
        """启动日志监控"""
        try:
            # 初始加载日志
            self.refresh_log()
            
            # 启动自动刷新定时器
            self.schedule_log_refresh()
            
        except Exception as e:
            logger.error(f"启动日志监控失败: {str(e)}")
    
    def schedule_log_refresh(self) -> None:
        """定时刷新日志"""
        try:
            # 如果启用自动刷新，则检查日志文件是否有更新
            if self.auto_refresh_var.get() and hasattr(self, 'log_text'):
                current_size = 0
                if os.path.exists(self.log_file_path):
                    current_size = os.path.getsize(self.log_file_path)
                
                # 如果文件大小发生变化，则刷新显示
                if current_size != self.last_log_size:
                    self.refresh_log()
                    self.last_log_size = current_size
            
            # 每2秒检查一次
            self.root.after(2000, self.schedule_log_refresh)
            
        except Exception as e:
            logger.error(f"定时刷新日志失败: {str(e)}")
            # 即使出错也要继续调度
            self.root.after(5000, self.schedule_log_refresh)
    
    # ==================== 全量日志模块功能方法 ====================
    
    def auto_load_eve_log(self):
        """
        自动加载EVE日志文件（在告警模块完成后调用）
        """
        if not self.current_pcap_dir:
            return
        
        # 尝试在数据包目录下查找eve.json文件
        # 优先查找最新的suricata_output目录
        eve_file_path = None
        suricata_dirs = []
        
        # 查找所有suricata_output目录
        for item in os.listdir(self.current_pcap_dir):
            if item.startswith("suricata_output"):
                suricata_dirs.append(item)
        
        if suricata_dirs:
            # 按时间戳排序，选择最新的
            # 安全地提取时间戳，如果无法解析则使用0
            def safe_extract_timestamp(dir_name):
                try:
                    if '_' in dir_name:
                        last_part = dir_name.split('_')[-1]
                        # 检查是否为纯数字
                        if last_part.isdigit():
                            return int(last_part)
                except (ValueError, IndexError):
                    pass
                return 0
            
            suricata_dirs.sort(key=safe_extract_timestamp, reverse=True)
            latest_dir = suricata_dirs[0]
            eve_file_path = os.path.join(self.current_pcap_dir, latest_dir, "eve.json")
        else:
            # 兼容旧版本，查找不带时间戳的目录
            eve_file_path = os.path.join(self.current_pcap_dir, "suricata_output", "eve.json")
        
        if os.path.exists(eve_file_path):
            try:
                self.current_eve_file = eve_file_path
                self.eve_events = self.eve_parser.parse_eve_json(eve_file_path)
                self.current_eve_event = None  # 清除当前事件
                self.copy_json_button.config(state=tk.DISABLED)  # 禁用复制按钮
                self.refresh_eve_log_list()
                self.eve_status_var.set(f"已自动加载 {len(self.eve_events)} 条EVE日志")
                logger.info(f"自动加载EVE日志文件成功: {eve_file_path}")
                
            except Exception as e:
                logger.error(f"自动加载EVE日志文件失败: {str(e)}")
                self.eve_status_var.set("自动加载EVE日志失败")
        else:
            self.eve_status_var.set("未找到EVE日志文件，请先运行告警模块分析")
    
    def refresh_eve_log(self):
        """
        刷新EVE日志列表
        """
        if not self.current_eve_file:
            messagebox.showwarning("警告", "请先运行告警模块分析以加载EVE日志")
            return
        
        try:
            self.eve_events = self.eve_parser.parse_eve_json(self.current_eve_file)
            self.current_eve_event = None  # 清除当前事件
            self.copy_json_button.config(state=tk.DISABLED)  # 禁用复制按钮
            self.refresh_eve_log_list()
            self.eve_status_var.set(f"已刷新，共 {len(self.eve_events)} 条日志")
        except Exception as e:
            messagebox.showerror("错误", f"刷新EVE日志失败: {str(e)}")
            self.eve_status_var.set("刷新失败")
    
    def clear_eve_log(self):
        """
        清空EVE日志列表
        """
        self.eve_events.clear()
        self.current_eve_event = None  # 清除当前事件
        self.copy_json_button.config(state=tk.DISABLED)  # 禁用复制按钮
        self.refresh_eve_log_list()
        self.eve_status_var.set("日志列表已清空")
    
    def refresh_eve_log_list(self):
        """
        刷新EVE日志列表显示
        """
        # 清空现有项目
        for item in self.eve_tree.get_children():
            self.eve_tree.delete(item)
        
        # 获取搜索和过滤条件
        search_text = self.eve_search_var.get().lower()
        event_type_filter = self.event_type_filter.get()
        protocol_filter = self.eve_protocol_filter.get()
        
        # 过滤事件
        filtered_events = []
        for event in self.eve_events:
            # 应用事件类型过滤
            if event_type_filter != "全部" and event.get('event_type', '') != event_type_filter:
                continue
            
            # 应用协议过滤
            if protocol_filter != "全部" and protocol_filter not in event.get('proto', '').upper():
                continue
            
            # 应用搜索过滤
            if search_text:
                if not self.matches_eve_search(event, search_text):
                    continue
            
            filtered_events.append(event)
        
        # 显示事件
        for event in filtered_events:
            # 获取URL或域名信息
            url_domain = ""
            if event.get('event_type') == 'http':
                url_domain = event.get('url', '')
            elif event.get('event_type') == 'dns':
                url_domain = event.get('dns_rrname', '')
            elif event.get('event_type') == 'tls':
                url_domain = event.get('tls_sni', '')
            
            # 截断URL/域名显示
            if len(url_domain) > 40:
                url_domain = url_domain[:37] + "..."
            
            self.eve_tree.insert("", "end", values=(
                event.get('src_ip', ''),
                event.get('src_port', ''),
                event.get('dest_ip', ''),
                event.get('dest_port', ''),
                url_domain
            ))
        
        # 更新状态栏
        if search_text or event_type_filter != "全部" or protocol_filter != "全部":
            self.eve_status_var.set(f"显示 {len(filtered_events)} 条日志 (已过滤，共 {len(self.eve_events)} 条)")
        else:
            self.eve_status_var.set(f"显示 {len(self.eve_events)} 条日志")
    
    def matches_eve_search(self, event: dict, search_text: str) -> bool:
        """
        检查事件是否匹配搜索条件
        
        Args:
            event: 事件信息
            search_text: 搜索文本
            
        Returns:
            bool: 是否匹配
        """
        if not search_text:
            return True
        
        search_text = search_text.lower()
        
        # 搜索各种字段
        searchable_fields = [
            str(event.get('src_ip', '')),
            str(event.get('dest_ip', '')),
            str(event.get('src_port', '')),
            str(event.get('dest_port', '')),
            event.get('proto', ''),
            event.get('event_type', ''),
            event.get('url', ''),
            event.get('hostname', ''),
            event.get('dns_rrname', ''),
            event.get('tls_sni', ''),
            event.get('http_user_agent', ''),
            event.get('http_method', ''),
            str(event.get('status', '')),
            event.get('http_content_type', ''),
            event.get('http_refer', '')
        ]
        
        return any(search_text in field.lower() for field in searchable_fields)
    
    def on_eve_search_change(self, event=None):
        """
        EVE日志搜索条件改变时的处理
        """
        self.refresh_eve_log_list()
    
    def clear_eve_search(self):
        """
        清除EVE日志搜索条件
        """
        self.eve_search_var.set("")
        self.event_type_filter.set("全部")
        self.eve_protocol_filter.set("全部")
        self.refresh_eve_log_list()
        self.eve_status_var.set("搜索已清除")
    
    def on_eve_select(self, event=None):
        """
        EVE日志选择事件处理
        """
        selected_items = self.eve_tree.selection()
        if not selected_items:
            return
        
        # 获取选中的事件索引
        item = selected_items[0]
        item_index = self.eve_tree.index(item)
        
        # 获取搜索和过滤条件
        search_text = self.eve_search_var.get().lower()
        event_type_filter = self.event_type_filter.get()
        protocol_filter = self.eve_protocol_filter.get()
        
        # 重新过滤事件以获取正确的索引
        filtered_events = []
        for event in self.eve_events:
            # 应用事件类型过滤
            if event_type_filter != "全部" and event.get('event_type', '') != event_type_filter:
                continue
            
            # 应用协议过滤
            if protocol_filter != "全部" and protocol_filter not in event.get('proto', '').upper():
                continue
            
            # 应用搜索过滤
            if search_text:
                if not self.matches_eve_search(event, search_text):
                    continue
            
            filtered_events.append(event)
        
        # 获取对应的事件数据
        if 0 <= item_index < len(filtered_events):
            event = filtered_events[item_index]
            self.show_eve_event_detail(event)
    
    def on_eve_double_click(self, event):
        """
        双击EVE日志事件处理
        """
        self.on_eve_select(event)
    
    def show_eve_event_detail(self, event: dict):
        """
        显示EVE事件详情
        
        Args:
            event: 事件数据
        """
        # 清空详情显示
        self.eve_detail_text.config(state=tk.NORMAL)
        self.eve_detail_text.delete(1.0, tk.END)
        
        try:
            import json
            import urllib.parse
            
            # 获取协议信息
            proto = event.get('proto', '')
            src_ip = event.get('src_ip', '')
            src_port = event.get('src_port', '')
            dest_ip = event.get('dest_ip', '')
            dest_port = event.get('dest_port', '')
            
            # 插入节点信息
            self.eve_detail_text.insert(tk.END, f"节点 1: IP 地址 = {src_ip}, {proto} 端口 = {src_port}\n")
            self.eve_detail_text.insert(tk.END, f"节点 2: IP 地址 = {dest_ip}, {proto} 端口 = {dest_port}\n\n")
            
            # 根据事件类型添加特定信息
            event_type = event.get('event_type', '')
            
            if event_type == 'http':
                # HTTP请求行（绿色）
                http_method = event.get('http_method', '')
                url = event.get('url', '')
                protocol = event.get('protocol', 'HTTP/1.1')
                
                self.eve_detail_text.insert(tk.END, f"{http_method} {url} {protocol}\n")
                
                # 请求头（绿色）
                request_headers = event.get('request_headers', {})
                if request_headers:
                    for key, value in request_headers.items():
                        self.eve_detail_text.insert(tk.END, f"{key}: {value}\n")
                
                self.eve_detail_text.insert(tk.END, "\n")
                
                # 请求体（绿色）
                request_body = event.get('http_request_body', '')
                if request_body:
                    # URL解码
                    try:
                        decoded_body = urllib.parse.unquote(request_body)
                    except:
                        decoded_body = request_body
                    
                    # 处理换行符
                    if '%0a' in decoded_body or '%0d' in decoded_body:
                        decoded_body = decoded_body.replace('%0a', '\n').replace('%0d', '\r')
                    
                    self.eve_detail_text.insert(tk.END, f"{decoded_body}\n\n")
                
                # HTTP响应行（蓝色）
                status = event.get('status', '')
                self.eve_detail_text.insert(tk.END, f"HTTP/1.1 {status} OK\n")
                
                # 响应头（蓝色）
                response_headers = event.get('response_headers', {})
                if response_headers:
                    for key, value in response_headers.items():
                        self.eve_detail_text.insert(tk.END, f"{key}: {value}\n")
                
                self.eve_detail_text.insert(tk.END, "\n")
                
                # 响应体（蓝色）
                response_body = event.get('http_response_body', '')
                if response_body:
                    # 处理换行符
                    if '%0a' in response_body or '%0d' in response_body:
                        response_body = response_body.replace('%0a', '\n').replace('%0d', '\r')
                    
                    self.eve_detail_text.insert(tk.END, f"{response_body}\n")
            
            elif event_type == 'dns':
                dns_type = event.get('dns_type', '')
                dns_rrname = event.get('dns_rrname', '')
                dns_rrtype = event.get('dns_rrtype', '')
                dns_rdata = event.get('dns_rdata', '')
                
                self.eve_detail_text.insert(tk.END, f"DNS查询: {dns_type} {dns_rrname} {dns_rrtype}\n")
                if dns_rdata:
                    self.eve_detail_text.insert(tk.END, f"响应: {dns_rdata}\n")
                
                # DNS应答
                dns_answers = event.get('dns_answers', [])
                if dns_answers:
                    self.eve_detail_text.insert(tk.END, "\nDNS应答:\n")
                    for answer in dns_answers:
                        self.eve_detail_text.insert(tk.END, f"  {answer}\n")
            
            elif event_type == 'tls':
                tls_version = event.get('tls_version', '')
                tls_sni = event.get('tls_sni', '')
                tls_subject = event.get('tls_subject', '')
                
                self.eve_detail_text.insert(tk.END, f"TLS版本: {tls_version}\n")
                if tls_sni:
                    self.eve_detail_text.insert(tk.END, f"服务器名称指示: {tls_sni}\n")
                if tls_sni:
                    self.eve_detail_text.insert(tk.END, f"证书主题: {tls_subject}\n")
            
            elif event_type == 'alert':
                alert_signature = event.get('alert_signature', '')
                alert_signature_id = event.get('alert_signature_id', '')
                alert_category = event.get('alert_category', '')
                
                self.eve_detail_text.insert(tk.END, f"告警签名: {alert_signature}\n")
                self.eve_detail_text.insert(tk.END, f"签名ID: {alert_signature_id}\n")
                self.eve_detail_text.insert(tk.END, f"分类: {alert_category}\n")
            
            elif event_type == 'fileinfo':
                filename = event.get('filename', '')
                file_size = event.get('file_size', '')
                file_type = event.get('file_type', '')
                
                self.eve_detail_text.insert(tk.END, f"文件名: {filename}\n")
                self.eve_detail_text.insert(tk.END, f"文件大小: {file_size} 字节\n")
                self.eve_detail_text.insert(tk.END, f"文件类型: {file_type}\n")
            
            # 应用颜色标签
            self._apply_http_colors()
            
        except Exception as e:
            self.eve_detail_text.insert(tk.END, f"显示事件详情失败: {str(e)}")
        
        self.eve_detail_text.config(state=tk.DISABLED)
        
        # 启用复制按钮
        self.copy_json_button.config(state=tk.NORMAL)
        
        # 保存当前事件的原始数据用于复制
        self.current_eve_event = event
    
    def copy_eve_json(self):
        """
        复制当前EVE事件的JSON数据到剪贴板
        """
        try:
            if hasattr(self, 'current_eve_event') and self.current_eve_event:
                # 获取原始事件数据
                raw_event = self.current_eve_event.get('raw_event', {})
                
                # 转换为格式化的JSON字符串
                import json
                json_str = json.dumps(raw_event, indent=2, ensure_ascii=False)
                
                # 复制到剪贴板
                self.root.clipboard_clear()
                self.root.clipboard_append(json_str)
                
                # 显示成功消息
                self.eve_status_var.set("JSON数据已复制到剪贴板")
                
                # 2秒后恢复原状态
                self.root.after(2000, lambda: self.eve_status_var.set(f"显示 {len(self.eve_events)} 条日志"))
                
            else:
                self.eve_status_var.set("没有可复制的事件数据")
                
        except Exception as e:
            self.eve_status_var.set(f"复制失败: {str(e)}")
            logger.error(f"复制EVE JSON数据失败: {str(e)}")
    
    def _apply_http_colors(self):
        """
        为HTTP内容应用颜色标签
        """
        try:
            # 配置颜色标签
            self.eve_detail_text.tag_config("request", foreground="green")
            self.eve_detail_text.tag_config("response", foreground="blue")
            
            # 获取文本内容
            content = self.eve_detail_text.get("1.0", tk.END)
            lines = content.split('\n')
            
            # 清除现有标签
            for tag in ["request", "response"]:
                self.eve_detail_text.tag_remove(tag, "1.0", tk.END)
            
            # 应用颜色标签
            current_line = 1
            in_request_section = False
            in_response_section = False
            
            for line in lines:
                line_start = f"{current_line}.0"
                line_end = f"{current_line}.end"
                
                # 检测请求部分开始
                if line.strip() and not line.startswith("节点") and not line.startswith("DNS") and not line.startswith("TLS") and not line.startswith("告警") and not line.startswith("文件"):
                    if line.startswith("HTTP/1.1"):
                        in_request_section = False
                        in_response_section = True
                    elif not in_response_section:
                        in_request_section = True
                
                # 应用颜色标签
                if in_request_section and line.strip():
                    self.eve_detail_text.tag_add("request", line_start, line_end)
                elif in_response_section and line.strip():
                    self.eve_detail_text.tag_add("response", line_start, line_end)
                
                current_line += 1
                
        except Exception as e:
            logger.error(f"应用HTTP颜色标签失败: {str(e)}")
    
    def _format_headers(self, headers: dict) -> str:
        """
        格式化HTTP头信息
        
        Args:
            headers: 头信息字典
            
        Returns:
            格式化后的字符串
        """
        if not headers:
            return "无"
        
        formatted = ""
        for key, value in headers.items():
            formatted += f"  {key}: {value}\n"
        
        return formatted.strip()
    
    def _format_dns_answers(self, answers: list) -> str:
        """
        格式化DNS应答信息
        
        Args:
            answers: DNS应答列表
            
        Returns:
            格式化后的字符串
        """
        if not answers:
            return "无"
        
        formatted = ""
        for i, answer in enumerate(answers, 1):
            formatted += f"  {i}. {answer}\n"
        
        return formatted.strip()


class ServerConfigDialog:
    """
    服务器配置对话框
    """
    
    def __init__(self, parent):
        """
        初始化服务器配置对话框
        
        Args:
            parent: 父窗口
        """
        self.result = None
        
        # 创建对话框
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("服务器配置")
        self.dialog.geometry("500x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 100, parent.winfo_rooty() + 100))
        
        # 创建界面
        self.create_widgets()
        
        # 加载上次配置
        self.load_last_config()
        
        # 等待对话框关闭
        self.dialog.wait_window()
    
    def load_last_config(self):
        """
        加载上次的配置信息
        """
        if not REMOTE_CONNECT_AVAILABLE:
            return
        
        try:
            config_manager = ConfigManager()
            last_config = config_manager.load_config()
            
            if last_config:
                # 填充配置信息
                self.host_var.set(last_config.get('host', ''))
                self.port_var.set(str(last_config.get('port', 22)))
                self.username_var.set(last_config.get('username', ''))
                self.password_var.set(last_config.get('password', ''))
                
                # 显示加载提示
                self.status_var.set(f"✅ 已加载上次配置 (使用时间: {last_config.get('last_used', '未知')})")
                
                print(f"📋 已加载上次配置:")
                print(f"   服务器: {last_config.get('host', 'N/A')}:{last_config.get('port', 'N/A')}")
                print(f"   用户: {last_config.get('username', 'N/A')}")
                if last_config.get('password'):
                    print(f"   密码: {'*' * len(last_config.get('password', ''))} (已加载)")
        except Exception as e:
            print(f"⚠️ 加载配置失败: {e}")
            self.status_var.set("⚠️ 加载配置失败")
    
    def create_widgets(self):
        """
        创建对话框组件
        """
        # 主框架
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 服务器信息区域
        server_frame = ttk.LabelFrame(main_frame, text="服务器信息", padding="5")
        server_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 主机地址
        ttk.Label(server_frame, text="主机地址:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.host_var = tk.StringVar()
        ttk.Entry(server_frame, textvariable=self.host_var, width=30).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        
        # 端口
        ttk.Label(server_frame, text="SSH端口:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.port_var = tk.StringVar(value="22")
        ttk.Entry(server_frame, textvariable=self.port_var, width=30).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        
        # 用户名
        ttk.Label(server_frame, text="用户名:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.username_var = tk.StringVar()
        ttk.Entry(server_frame, textvariable=self.username_var, width=30).grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        
        # 密码
        ttk.Label(server_frame, text="密码:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.password_var = tk.StringVar()
        ttk.Entry(server_frame, textvariable=self.password_var, show="*", width=30).grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        
        # 远程路径
        ttk.Label(server_frame, text="远程路径:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.remote_path_var = tk.StringVar(value="/var/lib/suricata/rules/suricata.rules")
        ttk.Entry(server_frame, textvariable=self.remote_path_var, width=30).grid(row=4, column=1, sticky=(tk.W, tk.E), padx=(5, 0), pady=2)
        
        # 配置网格权重
        server_frame.columnconfigure(1, weight=1)
        
        # 认证方式选择
        auth_frame = ttk.LabelFrame(main_frame, text="认证方式", padding="5")
        auth_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.auth_method = tk.StringVar(value="password")
        ttk.Radiobutton(auth_frame, text="密码认证", variable=self.auth_method, value="password").pack(anchor=tk.W)
        ttk.Radiobutton(auth_frame, text="密钥文件认证", variable=self.auth_method, value="key").pack(anchor=tk.W)
        
        # 密钥文件路径
        key_frame = ttk.Frame(auth_frame)
        key_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(key_frame, text="密钥文件:").pack(side=tk.LEFT)
        self.key_path_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.key_path_var, width=30).pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        ttk.Button(key_frame, text="浏览", command=self.browse_key_file).pack(side=tk.RIGHT)
        
        # 测试连接按钮
        test_frame = ttk.Frame(main_frame)
        test_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(test_frame, text="测试连接", command=self.test_connection).pack(side=tk.LEFT)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="确定", command=self.on_ok).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="取消", command=self.on_cancel).pack(side=tk.RIGHT)
        
        # 状态标签
        self.status_var = tk.StringVar(value="")
        ttk.Label(main_frame, textvariable=self.status_var, foreground="blue").pack(anchor=tk.W, pady=(5, 0))
    
    def browse_key_file(self):
        """
        浏览密钥文件
        """
        file_path = filedialog.askopenfilename(
            title="选择SSH私钥文件",
            filetypes=[("私钥文件", "*.pem *.key"), ("所有文件", "*.*")]
        )
        if file_path:
            self.key_path_var.set(file_path)
    
    def test_connection(self):
        """
        测试服务器连接
        """
        if not REMOTE_CONNECT_AVAILABLE:
            messagebox.showerror("错误", "remote_connect 模块不可用")
            return
        
        # 获取配置信息
        host = self.host_var.get().strip()
        port = int(self.port_var.get().strip()) if self.port_var.get().strip() else 22
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        
        if not host or not username:
            messagebox.showwarning("警告", "请填写主机地址和用户名")
            return
        
        if self.auth_method.get() == "password" and not password:
            messagebox.showwarning("警告", "请填写密码")
            return
        
        if self.auth_method.get() == "key" and not self.key_path_var.get().strip():
            messagebox.showwarning("警告", "请选择密钥文件")
            return
        
        try:
            self.status_var.set("正在测试连接...")
            self.dialog.update()
            
            # 创建连接对象
            if self.auth_method.get() == "key":
                # 密钥认证（需要修改RemoteServer类以支持密钥认证）
                server = RemoteServer(host, port, username, password)
                # TODO: 添加密钥认证支持
                messagebox.showwarning("提示", "密钥认证功能正在开发中，请使用密码认证")
                return
            else:
                # 密码认证
                server = RemoteServer(host, port, username, password)
            
            # 测试连接（带重试机制）
            if server.connect(max_retries=2, retry_delay=1.0):
                self.status_var.set("✅ 连接成功！")
                
                # 获取服务器信息
                try:
                    _, hostname_output, _ = server.execute_command("hostname")
                    _, uptime_output, _ = server.execute_command("uptime")
                    hostname = hostname_output.strip() if hostname_output else "未知"
                    uptime = uptime_output.strip() if uptime_output else "未知"
                    
                    success_msg = f"""✅ 服务器连接测试成功！

服务器信息：
- 主机名: {hostname}
- 运行时间: {uptime}
- 连接地址: {host}:{port}
- 用户: {username}"""
                    
                    messagebox.showinfo("连接成功", success_msg)
                except Exception:
                    messagebox.showinfo("连接成功", "服务器连接测试成功！")
                
                # 保存配置（如果连接成功）
                try:
                    config_manager = ConfigManager()
                    config_manager.save_config(host, port, username, password)
                    print("✅ 配置已保存")
                except Exception as e:
                    print(f"⚠️ 配置保存失败: {e}")
                
                server.disconnect()
            else:
                # 连接失败，进行网络诊断
                self.status_var.set("正在诊断网络连接...")
                self.dialog.update()
                
                diagnosis = NetworkDiagnostic.diagnose_connection(host, port)
                
                # 构建诊断报告
                diagnostic_info = "网络诊断结果：\n"
                diagnostic_info += f"- DNS解析: {'✅ 正常' if diagnosis['dns_resolution'] else '❌ 失败'}\n"
                diagnostic_info += f"- 主机连通性: {'✅ 可达' if diagnosis['host_reachable'] else '❌ 不可达'}\n"
                diagnostic_info += f"- SSH端口({port}): {'✅ 开放' if diagnosis['port_open'] else '❌ 关闭'}\n"
                
                if diagnosis['suggestions']:
                    diagnostic_info += "\n建议的解决方案：\n"
                    for i, suggestion in enumerate(diagnosis['suggestions'], 1):
                        diagnostic_info += f"{i}. {suggestion}\n"
                
                error_msg = f"""❌ 服务器连接测试失败

{diagnostic_info}
其他检查项：
• 确认用户名和密码是否正确
• 检查SSH服务配置
• 确认防火墙规则"""
                
                self.status_var.set("❌ 连接失败")
                messagebox.showerror("连接失败", error_msg)
        
        except Exception as e:
            self.status_var.set(f"❌ 连接错误: {str(e)}")
            messagebox.showerror("错误", f"连接测试失败: {str(e)}")
    
    def on_ok(self):
        """
        确定按钮事件
        """
        # 验证必填字段
        if not self.host_var.get().strip():
            messagebox.showwarning("警告", "请填写主机地址")
            return
        
        if not self.username_var.get().strip():
            messagebox.showwarning("警告", "请填写用户名")
            return
        
        if self.auth_method.get() == "password" and not self.password_var.get().strip():
            messagebox.showwarning("警告", "请填写密码")
            return
        
        if self.auth_method.get() == "key" and not self.key_path_var.get().strip():
            messagebox.showwarning("警告", "请选择密钥文件")
            return
        
        # 保存配置
        try:
            if REMOTE_CONNECT_AVAILABLE:
                config_manager = ConfigManager()
                config_manager.save_config(
                    host=self.host_var.get().strip(),
                    port=int(self.port_var.get().strip()) if self.port_var.get().strip() else 22,
                    username=self.username_var.get().strip(),
                    password=self.password_var.get().strip()
                )
                print("✅ 配置已保存到 connection_config.json")
        except Exception as e:
            print(f"⚠️ 配置保存失败: {e}")
        
        # 保存配置
        self.result = {
            "host": self.host_var.get().strip(),
            "port": int(self.port_var.get().strip()) if self.port_var.get().strip() else 22,
            "username": self.username_var.get().strip(),
            "password": self.password_var.get().strip(),
            "remote_path": self.remote_path_var.get().strip(),
            "auth_method": self.auth_method.get(),
            "key_path": self.key_path_var.get().strip()
        }
        
        self.dialog.destroy()
    
    def on_cancel(self):
        """
        取消按钮事件
        """
        self.dialog.destroy()


class RuleDialog:
    """
    规则编辑对话框
    """
    
    def __init__(self, parent, title: str, initial_rule: str = ""):
        """
        初始化对话框
        
        Args:
            parent: 父窗口
            title: 对话框标题
            initial_rule: 初始规则内容
        """
        self.result = None
        
        # 创建对话框
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("800x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        # 创建界面
        self.create_widgets(initial_rule)
        
        # 等待对话框关闭
        self.dialog.wait_window()
    
    def create_widgets(self, initial_rule: str):
        """
        创建对话框组件
        
        Args:
            initial_rule: 初始规则内容
        """
        # 主框架
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 规则内容标签
        ttk.Label(main_frame, text="规则内容:").pack(anchor=tk.W)
        
        # 规则内容文本框
        self.rule_text = scrolledtext.ScrolledText(main_frame, height=15, width=80)
        self.rule_text.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        self.rule_text.insert(tk.END, initial_rule)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="确定", command=self.on_ok).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="取消", command=self.on_cancel).pack(side=tk.RIGHT)
    
    def on_ok(self):
        """
        确定按钮事件
        """
        self.result = self.rule_text.get("1.0", tk.END).strip()
        self.dialog.destroy()
    
    def on_cancel(self):
        """
        取消按钮事件
        """
        self.dialog.destroy()


def main():
    """
    主函数
    """
    root = tk.Tk()
    app = SuricataRulesManager(root)
    root.mainloop()


if __name__ == "__main__":
    main() 