# System BlackBox

Windows 10/11 本地优先的系统事故记录与诊断工具。应用持续保存有界的低成本性能数据；问题发生后，用户可以保存故障前后的指标、Windows Event Log、进程快照和循环 BLG，并通过确定性规则或本地 Ollama 模型生成带证据引用的报告。

完整产品与技术规格见 [docs/spec.md](docs/spec.md)。

## 技术栈

- pnpm、Vue 3、TypeScript、Pinia、Vue Router
- Tauri 2、Rust、SQLite
- Windows PDH、IP Helper、`logman.exe`、`wevtutil.exe`
- Lucide 图标

## 开发

要求：

- Windows 10 或 Windows 11
- Node.js、pnpm
- Rust stable 与 Tauri 2 Windows 构建依赖

```powershell
pnpm install
pnpm build
pnpm tauri build
```

Rust 检查：

```powershell
cd src-tauri
cargo test
cargo check
```

## 使用

- 主界面“刚才发生了问题”会立即记录触发时间。
- 全局快捷键：`Ctrl + Shift + F12`。
- 关闭主窗口后应用继续驻留系统托盘；通过托盘菜单退出才会停止监控。
- Ollama 模式只接受 `localhost`、`127.0.0.1` 或 `::1` 端点。
- Dump 采集在 MVP 中固定关闭。

数据保存在 Tauri 应用数据目录，可从“隐私与数据”页面直接定位或删除。默认不登录、不遥测、不上传原始证据。
