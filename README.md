# 专业的 Suricata 入侵检测系统规则管理工具
> 🛡️ **专业的 Suricata 入侵检测系统规则管理工具**

一个功能强大的 Suricata 入侵检测系统规则管理工具，提供图形化界面来管理、编辑和分析 Suricata 规则文件。支持规则查看、编辑、搜索、过滤、远程部署等功能，是网络安全管理员和渗透测试人员的得力助手。

## 📋 项目简介

Suricata IDS 规则管理器是一个基于 Python Tkinter 开发的图形化工具，专门用于管理和维护 Suricata 入侵检测系统的规则文件。该工具提供了直观的用户界面，支持规则的查看、编辑、添加、删除、搜索和远程部署等功能。

## ✨ 主要功能

### 🔧 规则管理
- **规则查看**: 以树形结构显示所有 Suricata 规则
- **规则编辑**: 支持在线编辑规则内容
- **规则添加**: 通过图形界面添加新规则
- **规则删除**: 批量删除选中的规则
- **规则搜索**: 支持按内容、SID、类型、消息等多维度搜索
- **规则过滤**: 按告警类型、优先级、协议等条件过滤

### 📊 告警分析
- **实时告警**: 显示 Suricata 实时告警信息
- **告警统计**: 按类型、优先级、协议等维度统计告警
- **告警详情**: 查看告警的详细信息，包括源IP、目标IP、端口等
- **告警导出**: 支持将告警信息导出为文件

### 📈 全量日志分析
- **日志解析**: 解析 Suricata 全量日志文件
- **流量分析**: 分析网络流量模式和异常行为
- **数据包分析**: 支持 PCAP 文件分析
- **统计报表**: 生成流量统计报表

### 🌐 远程管理
- **SSH 连接**: 支持通过 SSH 连接到远程 Suricata 服务器
- **远程部署**: 将规则文件推送到远程服务器
- **配置管理**: 保存和管理多个服务器连接配置
- **批量操作**: 支持批量更新多个服务器的规则

## 🛠️ 技术特性

- **跨平台支持**: 支持 Windows、Linux、macOS
- **高性能**: 优化的规则解析和显示算法
- **用户友好**: 直观的图形化界面设计
- **扩展性强**: 模块化设计，易于扩展新功能
- **安全性**: 支持 SSH 密钥认证和密码加密存储

## 📦 安装要求

### 系统要求
- Python 3.6 或更高版本
- Windows 7/8/10/11 或 Linux/macOS
- 至少 2GB 可用内存
- 100MB 可用磁盘空间

### 依赖包
```
paramiko>=2.8.0
pyinstaller>=5.0
```

## 🚀 快速开始

### 🎯 快速演示

1. **下载项目**
   ```bash
   git clone <repository-url>
   cd suricata-rules-master
   ```

2. **一键安装（Windows）**
   ```
   双击 install_requirements.bat
   ```

3. **运行程序**
   ```bash
   python suricata_rules_manager.py
   ```

### 方法一：直接运行 Python 脚本

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd suricata-rules-master
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **运行程序**
   ```bash
   python suricata_rules_manager.py
   ```

### 方法二：使用批处理文件（Windows）

1. **双击运行安装脚本**
   ```
   双击 install_requirements.bat
   ```

2. **运行程序**
   ```
   双击 suricata_rules_manager.py
   ```

### 方法三：打包为可执行文件

1. **快速打包**
   ```
   双击 build.bat
   ```

2. **手动打包**
   ```bash
   python build_exe.py
   ```

3. **运行可执行文件**
   ```
   运行 dist/SuricataRulesManager.exe
   ```

## 📸 运行截图

### 主界面
![主界面](screenshots/main_interface.png)

主界面采用标签页设计，包含三个核心功能模块：
- **规则管理**: 用于管理 Suricata 规则文件，支持查看、编辑、添加、删除规则
- **告警模块**: 显示实时告警信息，提供告警分析和统计功能
- **全量日志**: 分析 Suricata 日志文件，支持流量分析和数据包分析

### 规则管理界面
![规则管理](screenshots/rules_management.png)

规则管理界面采用左右分栏设计：
- **左侧面板**: 规则树形结构显示，支持按类型、优先级等分类查看
- **右侧面板**: 规则详细信息和编辑区域，支持在线编辑规则内容
- **顶部工具栏**: 搜索和过滤功能，支持多维度规则查找
- **底部按钮区**: 常用操作按钮，包括添加、删除、保存等

### 告警分析界面
![告警分析](screenshots/alert_analysis.png)

告警分析界面提供全面的告警管理功能：
- **实时告警列表**: 显示最新的告警信息，包括时间、类型、优先级等
- **告警统计图表**: 可视化展示告警分布和趋势
- **告警详情查看**: 查看告警的详细信息，包括源IP、目标IP、端口等
- **告警导出功能**: 支持将告警信息导出为多种格式

### 远程连接配置
![远程连接](screenshots/remote_connection.png)

远程连接功能支持多服务器管理：
- **SSH 连接配置**: 支持密码和密钥认证方式
- **服务器管理**: 保存和管理多个服务器连接配置
- **规则文件推送**: 将本地规则文件推送到远程服务器
- **连接状态监控**: 实时显示连接状态和操作结果

## 📁 项目结构

```
suricata-rules-master/
├── suricata_rules_manager.py    # 主程序文件
├── remote_connect.py            # 远程连接模块
├── build_exe.py                 # 打包脚本
├── build.bat                    # Windows 打包批处理
├── install_requirements.bat     # 依赖安装脚本
├── requirements.txt             # Python 依赖包
├── connection_config.json       # 连接配置文件
├── suricata-ids.rules          # 示例规则文件
├── suricata_manager.log        # 程序日志文件
├── 打包说明.md                  # 打包详细说明
└── README.md                   # 项目说明文档
```

## 🔧 配置说明

### 连接配置文件 (connection_config.json)
```json
{
  "host": "192.168.1.100",
  "port": 22,
  "username": "admin",
  "password": "encoded_password",
  "last_used": "2024-01-01 12:00:00"
}
```

### 规则文件格式
支持标准的 Suricata 规则格式：
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg: "Rule Description";
    flow: established;
    content: "pattern";
    classtype: trojan-activity;
    sid: 1000001;
    rev: 1;
)
```

## 🎯 使用指南

### 1. 加载规则文件
1. 点击"选择文件"按钮
2. 选择 Suricata 规则文件 (.rules)
3. 程序会自动解析并显示规则

### 2. 搜索和过滤规则
1. 在搜索框中输入关键词
2. 选择搜索范围（全部、规则内容、SID等）
3. 使用过滤器按类型、优先级等条件筛选

### 3. 编辑规则
1. 在规则列表中选择要编辑的规则
2. 在右侧编辑区域修改规则内容
3. 点击"保存"按钮应用更改

### 4. 添加新规则
1. 点击"添加规则"按钮
2. 在弹出的对话框中输入规则内容
3. 设置规则的 SID 和其他参数
4. 点击"确定"保存规则

### 5. 远程部署
1. 配置远程服务器连接信息
2. 点击"推送服务器"按钮
3. 选择要推送的规则文件
4. 确认推送操作

## 🔍 故障排除

### 常见问题

1. **程序无法启动**
   - 检查 Python 版本是否为 3.6+
   - 确认已安装所有依赖包
   - 查看错误日志文件

2. **规则文件加载失败**
   - 检查规则文件格式是否正确
   - 确认文件编码为 UTF-8
   - 验证规则语法

3. **远程连接失败**
   - 检查网络连接
   - 确认 SSH 服务正常运行
   - 验证用户名和密码

4. **打包失败**
   - 确保 PyInstaller 已正确安装
   - 检查 Python 环境配置
   - 查看打包日志

### 日志文件
程序运行日志保存在 `suricata_manager.log` 文件中，包含详细的运行信息和错误记录。

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来改进这个项目。

### 开发环境设置
1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request

### 代码规范
- 遵循 PEP 8 Python 代码规范
- 添加适当的注释和文档字符串
- 确保代码通过所有测试

## 📄 许可证

本项目采用 MIT 许可证，详见 LICENSE 文件。

## 🙏 致谢

感谢以下开源项目的支持：
- [Suricata](https://suricata.io/) - 入侵检测系统
- [Paramiko](http://www.paramiko.org/) - SSH 协议实现
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - GUI 框架

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- 提交 GitHub Issue
- 发送邮件至项目维护者

---

**注意**: 本工具仅用于合法的网络安全管理和测试目的，请遵守相关法律法规。
