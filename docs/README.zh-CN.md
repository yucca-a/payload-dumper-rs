# payload-dumper-rs

[English](../README.md)

使用 Rust 原生重新实现的 Android OTA `payload.bin` 分区提取工具。

与 Python 版本相比，本项目新增了以下特性：

1. 直接从包含 `payload.bin` 的 **本地 ZIP** 归档中提取分区，无需解压（STORED 条目零拷贝读取）。
2. 直接从 **HTTP/HTTPS URL** 提取分区，无需下载整个 OTA 包。通过 HTTP Range 请求，仅按需获取所需字节。
3. 利用全部 CPU 核心的**并行**提取。
4. 完整支持 **ZIP64**，可处理大于 4 GB 的 OTA 包。
5. 既可作为 **命令行工具** 使用，也可作为 **Rust 库** 集成到其他项目。

## 环境要求

- Rust 1.80+（edition 2024）
- `cargo`

## 安装

```bash
cargo install --git https://github.com/yucca-a/payload-dumper-rs
```

或从源码构建：

```bash
git clone https://github.com/yucca-a/payload-dumper-rs
cd payload-dumper-rs
cargo build --release
# 二进制文件: target/release/payload-dumper
```

## 使用方法

### 列出 payload 中的分区

```bash
# 本地 payload.bin
payload-dumper list payload.bin

# 本地 OTA ZIP
payload-dumper list ota.zip

# 远程 URL —— 仅下载几 KB（中央目录 + manifest），不下载整包
payload-dumper list https://example.com/ota.zip
```

### 提取全部分区

```bash
payload-dumper extract ota.zip --out ./output
```

### 提取指定分区

使用逗号分隔的分区列表：

```bash
payload-dumper extract ota.zip --partitions boot,init_boot,vbmeta
```

### 从远程 URL 直接提取

```bash
# 无需下载完整 OTA，仅提取 boot 和 init_boot
payload-dumper extract https://example.com/ota.zip -p boot,init_boot --out ./output
```

## 作为库使用

```rust
use payload_dumper::payload::Payload;
use std::path::Path;

// 本地 payload.bin
let p = Payload::open(Path::new("payload.bin"))?;

// 本地 ZIP（STORED 条目零拷贝）
let p = Payload::open_at(Path::new("ota.zip"), data_offset)?;

// 远程 payload.bin URL
let p = Payload::open_url("https://example.com/payload.bin")?;

// 远程 OTA ZIP URL（自动通过 Range 请求解析中央目录，兼容 ZIP64）
let p = Payload::open_zip_url("https://example.com/ota.zip")?;

// 列出分区
for part in p.list_partitions() {
    println!("{}: {} 字节", part.name, part.size_bytes);
}

// 提取到目录（空切片 = 提取全部分区）
p.extract(Path::new("output"), &[])?;
```

## 致谢

- 灵感来源：[payload-dumper](https://github.com/5ec1cff/payload-dumper) by [5ec1cff](https://github.com/5ec1cff)
- 原始 payload-dumper 概念：[vm03](https://github.com/vm03/payload_dumper)
- Protobuf 定义来自 [AOSP update_engine](https://android.googlesource.com/platform/system/update_engine/)

## 许可证

[Apache-2.0](../LICENSE)
