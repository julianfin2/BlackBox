# System BlackBox — 产品与技术规格

> 文档类型：产品规格 / 技术架构规格  
> 目标平台：Windows 10 / Windows 11  
> 桌面技术栈：pnpm + Tauri 2 + Vue 3 + TypeScript  
> 后端核心：Rust  
> 文档状态：Draft v0.1

---

## 1. 产品概述

### 1.1 产品名称

暂定名：**System BlackBox**

中文定位：**Windows 系统故障黑匣子与 AI 诊断工具**

### 1.2 一句话说明

System BlackBox 是一个本地优先的 Windows 桌面诊断软件。

它在电脑正常运行时，以较低开销持续记录关键系统状态；当用户遇到卡死、无响应、网速异常、程序冻结、短时间严重卡顿等问题时，软件保存故障前后的“事故现场”，将来自性能计数器、ETW、Windows Event Log、进程状态和可选 dump 的信息整理成结构化证据，再由本地 AI 或用户明确授权的远程 AI 进行事后分析。

它不是实时聊天助手，也不是杀毒软件。

它的核心目标是：

> **解决“电脑刚才出了问题，但问题消失以后没有证据”的问题。**

---

## 2. 要解决的问题

Windows 上最难排查的问题通常不是稳定复现的错误，而是偶发问题，例如：

- 电脑突然完全卡住数秒或数分钟；
- 鼠标和窗口暂时无响应；
- 整个系统周期性变慢；
- 某个程序经常显示 Not Responding；
- CPU 看起来不高，但系统仍然严重卡顿；
- 磁盘偶尔 100% 活跃，原因不明确；
- GPU 驱动重置或桌面突然冻结；
- 网络偶尔变慢，但 Speedtest 之后又恢复正常；
- VPN、DNS、网卡、路由器、ISP 或电脑本身之间难以判断问题位置；
- 系统最终只能长按电源重启；
- 重启后事件查看器只剩下“上次关机异常”等结果，缺少故障发生前的上下文。

传统排查流程存在几个问题：

1. 用户通常在故障发生以后才开始收集数据；
2. 故障发生时用户无法同时打开多个诊断工具；
3. 不同证据分散在 Performance Monitor、Event Viewer、WPR/WPA、dump、网络工具等位置；
4. 原始数据量大，需要专业知识；
5. 单次日志很难发现“过去 10 次故障的共同模式”；
6. 上传完整 ETL、dump 和系统日志可能带来明显隐私风险。

System BlackBox 的目标不是保证找到所有根因，而是显著提高以下能力：

- 故障发生前保留证据；
- 将不同来源的数据按同一时间轴关联；
- 找出异常发生前的共同变化；
- 给出基于证据的原因排序；
- 明确区分“观察到的事实”“推测的原因”和“下一步验证方法”。

---

## 3. 产品原则

### 3.1 采集事实，不让 AI 负责测量

AI 不直接决定 CPU 是否高、磁盘是否慢、TCP 是否重传。

这些事实必须由确定性的系统工具和分析代码计算。

AI 的职责是：

- 解释结构化结果；
- 关联多个信号；
- 提出假设；
- 给出验证顺序；
- 用用户能理解的语言生成诊断报告。

### 3.2 默认本地处理

默认情况下：

- 原始日志不上传；
- dump 不上传；
- ETL 不上传；
- Windows Event Log 不上传；
- 文件名、用户名、路径和网络地址不发送到远程服务；
- AI 分析优先使用本地模型。

远程 AI 必须是用户显式开启的可选功能。

### 3.3 不从零重写系统采集能力

Windows 已经提供成熟的采集机制。

本项目第一阶段不自行实现以下底层能力：

- ETW 内核追踪；
- Windows Performance Counters；
- Windows Event Log；
- 用户态 dump 生成；
- Windows 崩溃转储机制。

软件主要负责：

- 配置；
- 启停；
- 触发；
- 冻结；
- 导出；
- 解析；
- 关联；
- 分析；
- 展示。

### 3.4 低成本常驻，高成本按需

不允许全天候开启所有高精度追踪。

采集分层：

1. 常驻低成本记录；
2. 环形高精度记录；
3. 故障触发后保存事故现场；
4. 必要时针对单个程序开启更重的专项采集。

### 3.5 结论必须附带证据

不允许只输出：

> 可能是驱动问题。

应输出：

- 观察到的异常；
- 异常发生时间；
- 与故障时间的距离；
- 相关进程、驱动或设备；
- 是否在多次事故中重复出现；
- 原因可信度；
- 下一步验证方法。

---

## 4. 核心用户场景

### 4.1 系统刚才卡了一下

用户发现电脑刚才严重卡顿 10 秒。

用户点击：

**“刚才发生了问题”**

软件：

1. 记录当前时间；
2. 冻结或复制环形缓冲区；
3. 保存故障前 N 分钟和故障后 M 秒数据；
4. 导出附近时间范围内的 Windows Event Log；
5. 建立 Incident；
6. 询问用户症状类型；
7. 完成结构化分析；
8. 生成报告。

### 4.2 系统完全死机后重启

用户长按电源后重新开机。

软件启动后发现：

- 上次运行没有正常关闭；
- 系统存在意外关机事件；
- 上一个采集会话留下了数据；
- 最后一条有效采样时间与关机时间接近。

软件自动提示：

**“检测到上次运行可能发生异常中断，是否创建事故记录？”**

然后整理：

- 死机前最后数分钟性能数据；
- 最后一批 ETW 数据；
- 系统和驱动事件；
- WHEA 事件；
- 磁盘、GPU、网络和服务异常；
- 可用的 minidump / memory dump。

### 4.3 某个程序经常无响应

用户选择程序，例如：

- Chrome；
- Teams；
- 自己开发的软件。

软件为该进程启用专项监控。

检测到窗口无响应后：

- 标记 Incident；
- 记录进程资源状态；
- 可选调用 ProcDump 生成 dump；
- 保存事件前后的系统上下文。

### 4.4 网速偶尔很慢

用户选择“网络问题”模式。

软件持续保存低成本网络指标：

- 当前网络接口；
- 链路速度；
- 上下行吞吐；
- 错误和丢弃；
- DNS 探测延迟；
- 默认网关延迟；
- 公网探测延迟；
- TCP 连接统计；
- VPN / 虚拟网卡状态；
- 网络配置变化。

用户点击“刚才网速很慢”后，软件分析：

- 是电脑整体卡顿还是纯网络问题；
- 本地网关是否异常；
- DNS 是否异常；
- 公网路径是否异常；
- 是否只在特定虚拟网卡或 VPN 开启时发生；
- 是否存在单个进程大量占用带宽。

---

## 5. 非目标

第一版明确不做：

- 自动修复所有 Windows 问题；
- 驱动自动升级；
- 注册表清理；
- 系统优化或“加速”；
- 杀毒；
- EDR；
- 防火墙替代；
- 自动修改 BIOS；
- 自动判断具体硬件已经物理损坏；
- 完整替代 WinDbg、WPA、Event Viewer；
- 长期保存所有原始网络数据包；
- 后台录屏；
- 键盘记录；
- 用户文件内容扫描。

---

## 6. 整体工作流

```text
Windows
   │
   ├── Performance Counters
   ├── ETW / WPR
   ├── Windows Event Log
   ├── WHEA / BugCheck / Reliability Events
   ├── Process State
   └── Optional ProcDump
          │
          ▼
┌──────────────────────────────┐
│ Collection Orchestrator      │
│ Rust / Windows integration   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Rolling Storage              │
│ Circular / bounded storage   │
└──────────────┬───────────────┘
               │
       Incident Trigger
               │
               ▼
┌──────────────────────────────┐
│ Incident Freezer             │
│ Freeze pre/post evidence     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Evidence Extractor           │
│ Convert raw data to facts    │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Correlation Engine           │
│ Timeline + anomaly scoring   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ AI Analysis Layer            │
│ Local first                  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Incident Report              │
│ Facts / hypotheses / tests   │
└──────────────────────────────┘
```

---

## 7. 数据采集架构

### 7.1 第一层：常驻低成本性能采集

用途：

- 全天候运行；
- 建立长期趋势；
- 捕获故障前资源变化；
- 找出周期性异常。

优先使用：

- Windows Performance Counters；
- `logman.exe`；
- 或后续由 Rust 直接读取 PDH API。

MVP 优先选择 `logman.exe`，避免过早重写稳定的系统能力。

记录格式：

- 原始：BLG；
- 结构化缓存：SQLite / Parquet 可选；
- Incident 生成时只提取相关时间窗口。

建议默认采样周期：

- 2 秒。

可配置：

- 1 秒；
- 2 秒；
- 5 秒；
- 10 秒。

默认保存上限：

- 1 GB 到 2 GB 循环日志。

建议指标类别：

#### CPU

- 总 CPU 使用率；
- 每核心使用率；
- Processor Queue Length；
- Privileged Time；
- User Time；
- Interrupt Time；
- DPC Time。

#### 内存

- Available Bytes；
- Committed Bytes；
- Commit Limit；
- Pages/sec；
- Page Reads/sec；
- Pool Paged Bytes；
- Pool Nonpaged Bytes。

#### 磁盘

- Disk Reads/sec；
- Disk Writes/sec；
- Avg. Disk sec/Read；
- Avg. Disk sec/Write；
- Current Disk Queue Length；
- Disk Transfers/sec；
- Free Space。

#### 进程

对重点进程记录：

- CPU；
- Working Set；
- Private Bytes；
- Handle Count；
- Thread Count；
- I/O Read Bytes/sec；
- I/O Write Bytes/sec。

不建议默认对所有进程保存所有计数器。

应采用：

- 系统总指标常驻；
- Top N 进程动态快照；
- 重点程序专项监控。

#### 网络接口

- Bytes Total/sec；
- Bytes Sent/sec；
- Bytes Received/sec；
- Packets Outbound Errors；
- Packets Received Errors；
- Packets Outbound Discarded；
- Packets Received Discarded。

### 7.2 第二层：ETW / WPR 环形高精度记录

用途：

- 分析短时卡顿；
- 定位 DPC / ISR；
- 分析线程调度；
- 分析磁盘 I/O；
- 分析驱动相关问题；
- 提供比普通性能计数器更细的事故现场。

优先使用：

- Windows Performance Recorder；
- 自定义 `.wprp` profile；
- Memory buffering / circular session。

原则：

- 高精度数据保存在受限的内存缓冲区；
- 新数据覆盖旧数据；
- Incident 发生时保存为 `.etl`；
- 保存后重新开始或继续记录。

MVP 不要求自己解析所有 ETL 内容。

第一阶段支持：

1. 创建和管理 WPR 会话；
2. 保存 ETL；
3. 获取基础元数据；
4. 调用现有 Windows 分析工具或导出器获得可解析结果；
5. 只对少数关键表实现自动提取。

建议第一版重点：

- CPU Usage；
- Disk I/O；
- DPC / ISR；
- Process / Thread lifetime；
- Context Switch；
- File I/O。

网络 ETW 作为后续扩展。

### 7.3 第三层：Windows Event Log

持续读取或事故后按时间窗口导出：

- System；
- Application。

重点 Provider / Event 类型：

- Kernel-Power；
- BugCheck；
- WHEA-Logger；
- Disk；
- Ntfs；
- StorPort；
- stornvme；
- Display；
- GPU 驱动相关 Provider；
- Service Control Manager；
- DNS Client；
- NetworkProfile；
- WLAN-AutoConfig；
- Application Hang；
- Application Error。

Incident 默认导出：

- 故障前 15 分钟；
- 故障后 5 分钟。

对于系统死机后重启：

- 读取上次正常采样结束时间；
- 以该时间为核心重新构造窗口。

### 7.4 第四层：程序无响应与 dump

可选集成：

- Microsoft Sysinternals ProcDump。

用途：

- 用户明确监控某个程序；
- 检测窗口 hang；
- CPU spike；
- 未处理异常；
- 生成用户态 dump。

默认行为：

- 不监控所有进程；
- 不自动生成所有程序的 full dump；
- 用户为具体程序开启；
- dump 大小受配额控制；
- 报告生成后提示用户保留或删除。

### 7.5 第五层：网络探测

网络问题不能只依赖网卡吞吐。

需要单独的轻量探测器。

建议周期性记录：

- 默认网关 RTT；
- 指定公网 IP RTT；
- DNS 查询延迟；
- DNS 查询失败；
- 当前默认路由；
- 当前 DNS；
- 当前活跃网络接口；
- 接口 metric；
- VPN / 虚拟网卡状态。

默认不保存：

- HTTP 内容；
- DNS 查询历史全文；
- 数据包 payload；
- 浏览历史。

后续可选加入：

- TCP retransmission summary；
- pktmon 摘要；
- 用户手动启动的短时 packet capture。

---

## 8. Incident 模型

Incident 是整个产品的核心业务对象。

### 8.1 创建方式

#### 手动创建

主按钮：

**“刚才发生了问题”**

用户选择：

- 系统卡顿；
- 系统无响应；
- 程序无响应；
- 网速慢；
- 网络断开；
- 黑屏 / 显示异常；
- 风扇突然高速；
- 自动重启；
- 蓝屏；
- 其他。

#### 快捷键创建

支持全局快捷键。

例如：

`Ctrl + Shift + F12`

用于窗口仍可操作但系统刚发生异常时。

#### 托盘创建

系统托盘菜单：

- Mark incident now；
- System freeze；
- Network slow；
- App not responding。

#### 自动创建

条件包括：

- 上次会话异常中断；
- 检测到 BugCheck；
- 检测到 WHEA 严重错误；
- 关键性能阈值持续异常；
- 受监控程序 hang；
- 系统发生意外重启。

### 8.2 时间窗口

每个 Incident 包含：

- `trigger_time`；
- `pre_window_start`；
- `post_window_end`。

默认：

- 前 10 分钟；
- 后 2 分钟。

不同症状可使用不同策略。

例如：

系统卡顿：

- 前 10 分钟；
- 后 2 分钟。

程序崩溃：

- 前 5 分钟；
- 后 30 秒。

网络变慢：

- 前 15 分钟；
- 后 5 分钟。

### 8.3 Incident 状态

```text
capturing
freezing
extracting
ready_for_analysis
analyzing
completed
failed
archived
```

---

## 9. 事故包格式

目录示例：

```text
incidents/
└── 2026-07-03T15-20-14Z_f3a81/
    ├── incident.json
    ├── user_report.json
    ├── evidence/
    │   ├── performance.blg
    │   ├── trace.etl
    │   ├── system.evtx
    │   ├── application.evtx
    │   ├── network.jsonl
    │   ├── process_snapshot.json
    │   └── dumps/
    ├── extracted/
    │   ├── metrics.parquet
    │   ├── events.jsonl
    │   ├── anomalies.json
    │   ├── correlations.json
    │   └── facts.json
    └── report/
        ├── report.json
        └── report.md
```

### 9.1 incident.json

```json
{
  "id": "f3a81",
  "created_at": "2026-07-03T15:20:14Z",
  "trigger_time": "2026-07-03T15:20:14Z",
  "trigger_source": "manual",
  "symptom": "system_freeze",
  "severity": "high",
  "pre_window_seconds": 600,
  "post_window_seconds": 120,
  "machine_id": "local-anonymous-id",
  "app_version": "0.1.0"
}
```

### 9.2 facts.json

只保存分析层需要的事实。

示例：

```json
{
  "incident_id": "f3a81",
  "observations": [
    {
      "type": "disk_latency_spike",
      "start_offset_ms": -4200,
      "end_offset_ms": -700,
      "device": "PhysicalDrive0",
      "baseline_ms": 8.3,
      "peak_ms": 4821.0,
      "severity": "critical"
    },
    {
      "type": "event_log_match",
      "offset_ms": -2400,
      "provider": "stornvme",
      "event_id": 129
    }
  ]
}
```

---

## 10. 数据处理管线

### 10.1 原始层

保存系统原始证据：

- BLG；
- ETL；
- EVTX；
- DMP；
- JSONL。

原始层不可由 AI 修改。

### 10.2 提取层

Rust 提取器负责转换：

```text
Raw evidence
   ↓
Normalized records
```

统一字段：

```text
timestamp
source
category
metric
value
unit
process_id
process_name
device
provider
event_id
metadata
```

### 10.3 异常检测层

先用确定性算法。

第一版可采用：

- 固定阈值；
- 滑动平均；
- rolling median；
- MAD；
- 基线倍数；
- 持续时间；
- 同类事件重复次数。

示例：

```text
磁盘延迟：

baseline = 最近 30 分钟中位数

如果：
latency > max(500ms, baseline × 20)

并持续：
>= 2 个采样点

则：
创建 disk_latency_spike
```

### 10.4 关联层

所有事件转换到同一时间轴。

分析：

- 异常距离 trigger 的时间；
- 两个异常是否同时出现；
- 多次 Incident 是否重复出现；
- 某进程是否只在事故前异常；
- 某驱动事件是否总在故障前出现。

输出：

```json
{
  "pattern": "storage_stall_before_freeze",
  "incident_count": 7,
  "matched_incidents": 6,
  "confidence": 0.86
}
```

### 10.5 AI 层

AI 输入不能直接是几 GB 的原始文件。

输入应由以下内容组成：

- 用户描述；
- Incident metadata；
- 关键事实；
- 异常；
- 关联结果；
- 历史 Incident 模式；
- 有限制的事件文本。

AI 输出必须符合 JSON Schema。

示例：

```json
{
  "summary": "系统冻结前发生严重存储 I/O 停顿。",
  "likely_causes": [
    {
      "title": "NVMe 设备或存储驱动异常",
      "confidence": 0.88,
      "supporting_evidence_ids": [
        "obs_21",
        "obs_34"
      ],
      "contradicting_evidence_ids": []
    }
  ],
  "next_tests": [
    {
      "title": "检查 SSD SMART 与固件",
      "priority": 1
    },
    {
      "title": "检查 stornvme 相关重复事件",
      "priority": 2
    }
  ]
}
```

---

## 11. AI 设计

### 11.1 本地优先

支持模式：

1. 无 AI；
2. 本地 AI；
3. 远程 AI。

默认：

- 无 AI 或本地 AI。

### 11.2 本地 AI 适配层

第一版优先支持：

- Ollama compatible API。

后续可扩展：

- llama.cpp server；
- LM Studio OpenAI-compatible endpoint；
- 自定义 OpenAI-compatible endpoint。

前端不直接调用模型。

调用路径：

```text
Vue
 ↓
Tauri Command
 ↓
Rust AI Adapter
 ↓
Local Model Endpoint
```

### 11.3 AI 不可信边界

AI 不能：

- 修改原始证据；
- 自动删除事故包；
- 自动执行修复命令；
- 自动修改驱动；
- 自动改注册表；
- 自动关闭安全功能。

第一版只生成：

- 分析；
- 解释；
- 验证步骤。

### 11.4 证据引用

报告中的每个原因必须引用：

- Observation ID；
- Event ID；
- 时间偏移；
- 数据来源。

UI 可点击证据跳转到时间线。

---

## 12. 隐私与安全设计

### 12.1 默认零上传

应用第一次启动时不要求登录。

默认：

- 无账号；
- 无云同步；
- 无遥测；
- 无原始日志上传。

### 12.2 敏感数据分级

#### Level 0：低敏感

- CPU 百分比；
- 内存使用量；
- 磁盘延迟；
- 网络延迟。

#### Level 1：中敏感

- 进程名；
- 驱动名；
- 设备型号；
- Event Provider。

#### Level 2：高敏感

- 用户名；
- 文件路径；
- 主机名；
- IP 地址；
- SSID；
- 命令行参数。

#### Level 3：极高敏感

- dump 内存；
- packet payload；
- 可能包含 token、密码、文档内容的内存数据。

UI 必须明确显示当前 Incident 包含哪个敏感等级。

### 12.3 远程 AI 脱敏

远程模式默认不发送原始文件。

只发送结构化摘要，并执行：

- 用户名替换；
- 路径匿名化；
- IP 模糊化；
- hostname 替换；
- SSID 替换；
- 命令行参数裁剪。

例如：

```text
C:\Users\Julian\Documents\Private\file.docx
```

变为：

```text
%USERPROFILE%\Documents\<redacted>\file.docx
```

### 12.4 dump 安全

完整 dump 可能包含：

- 密码；
- token；
- 页面内容；
- 文档内容；
- 私钥。

因此：

- 默认不开启全局 dump；
- 只对用户指定程序开启；
- 明确标记高敏感；
- 不允许自动上传远程 AI；
- 提供一键删除。

---

## 13. 技术架构

## 13.1 技术栈

### 包管理

- pnpm workspace。

### 桌面壳

- Tauri 2。

### 前端

- Vue 3；
- TypeScript；
- Vite；
- Pinia；
- Vue Router。

### 后端

- Rust；
- Tokio；
- Serde；
- SQLx 或 rusqlite；
- tracing。

### 本地数据库

- SQLite。

用途：

- 设置；
- Incident 索引；
- 结构化观察结果；
- 分析报告；
- 历史模式。

### 大型时序数据

MVP：

- 原始 BLG 保留；
- 提取后存 SQLite 或压缩 JSONL。

后续：

- Parquet。

不要把大型 ETW 事件全部写入 SQLite。

---

## 13.2 pnpm workspace 结构

```text
system-blackbox/
├── apps/
│   └── desktop/
│       ├── src/
│       ├── src-tauri/
│       ├── package.json
│       └── vite.config.ts
│
├── packages/
│   ├── ui/
│   ├── shared-types/
│   ├── schemas/
│   └── eslint-config/
│
├── tools/
│   ├── wpr-profiles/
│   ├── scripts/
│   └── fixtures/
│
├── docs/
│   ├── architecture/
│   ├── data-formats/
│   └── privacy/
│
├── pnpm-workspace.yaml
├── package.json
└── spec.md
```

---

## 13.3 Tauri 边界

Vue 负责：

- 界面；
- 状态展示；
- 图表；
- 用户输入；
- Incident 浏览；
- 报告展示。

Rust 负责：

- Windows API；
- 子进程管理；
- 管理员权限操作；
- 文件读写；
- SQLite；
- 数据提取；
- 事故冻结；
- AI 请求；
- 隐私脱敏。

禁止：

- Vue 直接执行 PowerShell；
- Vue 直接启动 `wpr.exe`；
- Vue 直接读取任意系统路径；
- 前端持有管理员逻辑。

---

## 13.4 Rust 模块划分

```text
src-tauri/src/
├── main.rs
├── app.rs
│
├── commands/
│   ├── monitoring.rs
│   ├── incidents.rs
│   ├── reports.rs
│   └── settings.rs
│
├── collector/
│   ├── mod.rs
│   ├── perfmon.rs
│   ├── etw.rs
│   ├── eventlog.rs
│   ├── network.rs
│   └── procdump.rs
│
├── incident/
│   ├── mod.rs
│   ├── trigger.rs
│   ├── freezer.rs
│   └── recovery.rs
│
├── evidence/
│   ├── mod.rs
│   ├── manifest.rs
│   ├── extractor.rs
│   └── sanitizer.rs
│
├── analysis/
│   ├── anomaly.rs
│   ├── correlation.rs
│   ├── baseline.rs
│   └── rules.rs
│
├── ai/
│   ├── mod.rs
│   ├── local.rs
│   ├── remote.rs
│   ├── prompt.rs
│   └── schema.rs
│
├── storage/
│   ├── database.rs
│   ├── files.rs
│   └── retention.rs
│
├── windows/
│   ├── privilege.rs
│   ├── service.rs
│   ├── process.rs
│   └── eventlog.rs
│
└── models/
```

---

## 14. 常驻进程与权限模型

### 14.1 MVP

MVP 使用：

- Tauri 主程序；
- 后台托盘；
- 必要操作时请求管理员权限。

缺点：

- 用户退出应用后无法持续记录；
- UAC 流程影响体验；
- 高权限子进程管理复杂。

### 14.2 正式版推荐架构

正式版拆分：

```text
System BlackBox UI
        │
        │ Local IPC
        ▼
System BlackBox Service
        │
        ├── Collectors
        ├── Incident Freezer
        ├── Storage
        └── Privileged operations
```

#### UI

运行权限：

- 普通用户。

职责：

- 展示；
- 配置；
- 创建 Incident；
- 报告。

#### Windows Service

运行权限：

- LocalSystem 或最低满足要求的服务账户。

职责：

- 开机启动；
- 持续采集；
- 管理 WPR；
- 事件日志读取；
- 事故冻结。

IPC 要求：

- Named Pipe；
- 身份验证；
- 消息 Schema；
- 不接受任意 shell command。

MVP 可以先不实现 Windows Service，但架构必须预留。

---

## 15. 前端页面

### 15.1 Dashboard

显示：

- Monitoring 状态；
- 已运行时间；
- 当前磁盘使用；
- 当前 ETW 缓冲状态；
- 最近 Incident；
- 当前 CPU / Memory / Disk / Network 概要。

核心按钮：

**刚才发生了问题**

这是产品最重要的操作入口。

### 15.2 Incident 创建弹窗

字段：

- 症状；
- 严重程度；
- 大约持续多久；
- 是否仍在发生；
- 可选描述。

要求：

- 10 秒内完成；
- 不强迫用户填写长文本。

### 15.3 Incident 列表

显示：

- 时间；
- 症状；
- 状态；
- 最可能原因；
- 可信度；
- 是否已分析。

### 15.4 Incident 详情

Tab：

1. Summary；
2. Timeline；
3. Evidence；
4. AI Analysis；
5. Raw Files。

### 15.5 Timeline

中心：

```text
0 = 用户标记故障时刻
```

显示：

```text
-10m                           0                  +2m
│                              │                    │
CPU       ────────▲────────────│────────────────────
Disk      ────────────────█████│────────────────────
Network   ──────────▼───────────│────────────────────
Events               ●      ●  │
ETW                       ▲     │
```

支持：

- 缩放；
- 过滤；
- 点击异常；
- 对齐事件；
- 显示 trigger。

### 15.6 Privacy 页面

显示：

- 当前收集哪些数据；
- 数据保存位置；
- 存储上限；
- 当前最敏感文件；
- 是否允许远程 AI；
- 一键删除所有数据。

---

## 16. 数据保留策略

默认：

### Rolling data

- 自动覆盖；
- 用户不能视为永久历史。

### Incident

默认保留：

- 30 天。

可选：

- 7 天；
- 30 天；
- 90 天；
- 永久。

### 存储配额

默认：

- Rolling performance：2 GB；
- ETW：内存受限；
- Incident raw evidence：20 GB 总上限；
- Dumps：10 GB 总上限。

超过限制：

1. 不删除 pinned Incident；
2. 优先删除最旧未固定 Incident；
3. dump 单独处理；
4. 删除前记录审计事件。

---

## 17. MVP 范围

### MVP 目标

证明以下闭环成立：

```text
持续记录
→
用户标记事故
→
保存故障前数据
→
提取异常
→
生成结构化事故报告
→
本地 AI 解释
```

### MVP 必须实现

#### 桌面框架

- pnpm；
- Tauri 2；
- Vue 3；
- TypeScript。

#### Monitoring

- 启动 / 停止；
- 当前状态；
- Performance Counter 循环采集；
- Event Log 时间窗口导出。

#### Incident

- 手动按钮；
- 症状选择；
- 保存前 10 分钟；
- 生成事故目录。

#### 分析

至少分析：

- CPU saturation；
- low available memory；
- commit pressure；
- disk latency spike；
- disk queue spike；
- network interface error；
- process CPU spike；
- Windows critical events。

#### AI

- Ollama compatible local endpoint；
- 结构化输入；
- JSON Schema 输出；
- 报告展示。

#### Privacy

- 默认无网络；
- 明确显示数据目录；
- 一键删除 Incident；
- dump 默认关闭。

### MVP 不做

- 自动识别所有程序 hang；
- Windows Service；
- 复杂 ETL 自动解析；
- 远程云账号；
- 多设备；
- 自动修复；
- packet capture；
- 完整 dump 分析；
- 驱动符号服务器；
- WinDbg 自动化。

---

## 18. 第二阶段

### 18.1 WPR 环形追踪

实现：

- 自定义 `.wprp`；
- 内存循环模式；
- Incident freeze；
- ETL 保存。

### 18.2 自动异常触发

规则：

- 磁盘延迟严重异常；
- 内存 Commit 接近极限；
- CPU 持续饱和；
- DPC / ISR 异常；
- 网络丢包；
- GPU reset event。

### 18.3 多事故模式分析

例如：

> 过去 8 次卡顿中，7 次在故障前 5 秒内出现存储延迟峰值。

### 18.4 Windows Service

保证：

- 开机采集；
- UI 关闭仍运行；
- 权限稳定。

---

## 19. 第三阶段

- ProcDump 管理；
- dump metadata 自动提取；
- WinDbg / debugger automation；
- 更完整 ETW parser；
- 网络专项诊断模式；
- pktmon 短时捕获；
- 可选远程 AI；
- 可导出的匿名诊断包；
- 技术人员模式；
- 用户授权后的修复建议执行。

---

## 20. 关键风险

### 20.1 采集本身影响系统

风险：

- 高采样频率；
- 过多 process counters；
- 过重 ETW profile；
- 大量磁盘写入。

措施：

- 默认低成本；
- 所有 collector 有资源预算；
- 内置自监控；
- 显示 BlackBox 自身 CPU、内存、磁盘写入；
- 超限自动降级。

### 20.2 整机硬锁死导致最后数据丢失

无法完全避免。

措施：

- 循环日志及时落盘；
- ETW memory + 可选 file mode；
- 限制写缓存；
- 重启后恢复未完成会话；
- 保存最后有效采样时间。

### 20.3 AI 误诊

措施：

- 规则层先输出事实；
- AI 只能引用已有 Evidence ID；
- 原因必须有支持证据；
- 允许输出“不足以判断”；
- 显示可信度；
- 提供验证实验。

### 20.4 dump 泄露隐私

措施：

- 默认关闭；
- 高敏感警告；
- 禁止自动远程上传；
- 独立配额；
- 一键删除。

### 20.5 Windows 版本差异

措施：

- Collector capability detection；
- 启动时自检；
- 不假设所有 Provider 都存在；
- 每个功能显示 supported / degraded / unavailable。

---

## 21. 验收标准

### 21.1 基础监控

应用运行 24 小时：

- 不发生无限日志增长；
- 循环存储按限制工作；
- 应用自身平均 CPU 占用保持低水平；
- 重启后能够恢复监控。

### 21.2 Incident

用户点击“刚才发生了问题”后：

- 立即记录 trigger time；
- 不因后续分析阻塞 UI；
- 成功保留事故前窗口；
- 生成完整 manifest；
- 可重新打开 Incident。

### 21.3 事故分析

模拟以下情况：

1. CPU 高负载；
2. 内存压力；
3. 磁盘高延迟；
4. 单进程 CPU spike；
5. 网络接口断开；
6. 手动制造 Application Error。

系统必须：

- 在正确时间线上显示；
- 生成 Observation；
- AI 报告引用对应 Evidence ID。

### 21.4 隐私

在默认设置下：

- 应用不要求账号；
- 不调用远程 AI；
- 不上传数据；
- 用户可定位所有本地数据；
- 用户可删除所有 Incident。

---

## 22. 开发顺序

### Milestone 1：项目骨架

- pnpm workspace；
- Tauri；
- Vue 3；
- SQLite；
- 基础设置；
- 系统托盘。

### Milestone 2：Performance BlackBox

- logman controller；
- 循环 BLG；
- 状态检查；
- 启停；
- 存储限制。

### Milestone 3：Incident

- 标记按钮；
- trigger time；
- 事故目录；
- 复制 / 截取相关数据；
- Event Log 导出。

### Milestone 4：Evidence Extractor

- BLG 转换；
- Event Log 转换；
- unified timeline；
- facts.json。

### Milestone 5：Rule Engine

- CPU；
- Memory；
- Disk；
- Network；
- Event correlation。

### Milestone 6：Local AI

- Ollama compatible adapter；
- Prompt builder；
- JSON Schema；
- 报告页面。

### Milestone 7：ETW / WPR

- WPR profile；
- 环形 session；
- Incident freeze；
- ETL 管理。

### Milestone 8：自动触发

- crash recovery；
- unexpected shutdown；
- critical events；
- threshold triggers。

---

## 23. 最小可行产品的最终定义

MVP 不追求“AI 修电脑”。

MVP 只需要可靠完成这件事：

> 用户电脑偶尔出现问题。  
> 问题发生后，用户按一下按钮。  
> 软件能拿出问题发生前的真实系统状态，告诉用户当时哪些指标异常、哪些事件同时发生，以及最值得优先验证的几个原因。

只要这个闭环可靠，产品就有实际价值。

---

## 24. 实现依据与参考

以下能力是本架构采用现成 Windows 采集工具而不是自行实现的主要依据：

- Windows Performance Recorder 基于 ETW，支持记录到文件或内存中的 circular buffers。
- ETW 支持 circular buffering，可用于持续日志与监控。
- WPR profile 支持 sequential file 和 circular memory logging。
- `logman` 可管理 Performance Logs 和 Event Trace Sessions。
- Performance Monitor / `logman` 可配置采样间隔和日志大小上限。
- ProcDump 支持 hung window monitoring、CPU spike 和异常触发的 dump。
- Tauri 2 支持使用 Vue 等现有前端技术栈，后端使用 Rust。

官方参考：

- https://v2.tauri.app/
- https://v2.tauri.app/start/create-project/
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/introduction-to-wpr
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/sessions
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/authoring-recording-profiles
- https://learn.microsoft.com/en-us/windows-hardware/test/weg/instrumenting-your-code-with-etw
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/troubleshoot-issues-performance-monitor
- https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
