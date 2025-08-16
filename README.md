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
  <img width="1920" height="976" alt="image" src="https://github.com/user-attachments/assets/ccbcb155-a571-4fed-89c2-f979c2713e1b" />


### 📊 告警分析
- **实时告警**: 显示 Suricata 实时告警信息
- **告警统计**: 按类型、优先级、协议等维度统计告警
- **告警详情**: 查看告警的详细信息，包括源IP、目标IP、端口等
- **告警导出**: 支持将告警信息导出为文件
  <img width="1920" height="979" alt="image" src="https://github.com/user-attachments/assets/b24bb61f-861d-4b61-be21-3b36404bd27e" />


### 📈 全量日志分析
- **日志解析**: 解析 Suricata 全量日志文件
- **流量分析**: 分析网络流量模式和异常行为
- **数据包分析**: 支持 PCAP 文件分析
- **统计报表**: 生成流量统计报表
  <img width="1920" height="985" alt="image" src="https://github.com/user-attachments/assets/7a860f07-2c4d-43f5-925a-5b7959af3ba4" />

## 🛠️ 技术特性

- **跨平台支持**: 支持 Windows、Linux、macOS
- **高性能**: 优化的规则解析和显示算法
- **用户友好**: 直观的图形化界面设计
- **扩展性强**: 模块化设计，易于扩展新功能
- **安全性**: 支持 SSH 密钥认证和密码加密存储

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
