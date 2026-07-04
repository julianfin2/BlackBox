# System BlackBox MVP 实现说明

本文档记录 `docs/spec.md` 中 MVP 与当前代码的对应关系。第二、第三阶段能力仍按规格保留为后续边界，不在 MVP 中伪装为可用功能。

## 采集与存储

| 规格要求 | 实现 |
| --- | --- |
| 1/2/5/10 秒低成本采样 | Rust 后台线程；设置经过后端白名单校验 |
| CPU、内存、Commit、磁盘、网络、进程 | `sysinfo`、PDH、`GlobalMemoryStatusEx`、`GetIfTable2` |
| 循环 Performance Counter | `logman.exe` 的 `bincirc` BLG；失败时显示降级状态 |
| 有界存储 | JSONL 与 BLG 分配同一滚动配额；事故包按期限和总配额清理 |
| 固定事故不自动删除 | 每个事故包使用本地 `.pinned` 标记 |
| SQLite | 事故索引、观察结果、报告与审计记录 |
| 自监控 | UI 显示 BlackBox 自身 CPU、内存和写入速率；开销过高时降低采样频率 |

## 事故闭环

1. 主按钮被点击时立即记录 `trigger_time`，表单填写不会改变触发时刻。
2. 后台继续采集症状对应的 post window，不阻塞 UI。
3. 冻结 rolling JSONL 与循环 BLG。
4. 使用 `wevtutil.exe` 导出 System/Application EVTX 和限定时间窗口的 XML。
5. 保存系统与重点进程快照。
6. 规则层生成 `facts.json`，报告层生成 `report.json` 与 `report.md`。
7. UI 提供摘要、可缩放/过滤/点击的时间线、证据、AI 分析和原始文件页面。

快捷入口：

- `Ctrl + Shift + F12`
- 系统托盘的系统无响应、网络缓慢、程序无响应
- 上次会话未正常结束时的恢复提示

## 确定性分析

当前规则覆盖：

- CPU 持续饱和
- 可用物理内存过低
- Commit 压力
- 磁盘延迟
- 磁盘队列
- 磁盘吞吐突增
- 单进程 CPU 峰值
- 网卡错误和丢弃
- Kernel-Power、WHEA、BugCheck、存储、显示、Application Hang/Error 事件

Windows Event XML 会提取 Provider、Event ID 和相对触发时间。没有达到阈值的事实时，报告明确输出“证据不足”，不会根据症状猜测根因。

## AI 与隐私边界

- 默认 `disabled`，不会发起网络请求。
- Ollama 只允许 `localhost`、`127.0.0.1` 和 `::1`。
- 输入是结构化 Observation，不发送 BLG、EVTX、Dump 或其他原始文件。
- 模型输出必须通过 Rust 结构反序列化、可信度范围检查和 Evidence ID 存在性检查。
- Dump 在 MVP 中固定关闭。
- 隐私页显示数据目录、敏感等级和分类存储用量，并可定位或删除全部本地诊断数据。

## 桌面行为

- 单实例运行，防止多个进程同时写数据。
- 关闭主窗口后隐藏到托盘，采集继续。
- 托盘左键恢复窗口，托盘菜单可以显式退出并停止采集。
- 原生全局快捷键和 Windows 安装包。
- UI 使用固定侧栏、工具栏、紧凑表格、状态栏和模态对话框，不采用网页落地页布局。

## 阶段边界

按规格，以下属于第二或第三阶段，MVP 不宣称已实现：

- WPR/ETW 高精度环形会话与完整 ETL 解析
- Windows Service 与 UI/服务 Named Pipe IPC
- 自动阈值触发
- ProcDump、Dump metadata、WinDbg 自动化
- pktmon、packet capture
- 远程 AI、云账号、多设备和自动修复
