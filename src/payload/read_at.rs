// payload::read_at — 随机访问读取抽象层
//
// 让 Payload 同时支持本地文件和 HTTP 远程文件，
// 提取逻辑无需修改即可复用。

use anyhow::Result;

/// 随机访问读取 trait（无需 seek，线程安全）。
///
/// 实现要求：Send + Sync，以支持 rayon 并行提取。
pub trait ReadAt: Send + Sync {
    /// 从 `offset` 处精确读取 `buf.len()` 字节。
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;

    /// 数据源总大小（可选）。
    fn size(&self) -> Option<u64> {
        None
    }
}

impl ReadAt for std::fs::File {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        use std::os::unix::fs::FileExt;
        Ok(FileExt::read_exact_at(self, buf, offset)?)
    }

    fn size(&self) -> Option<u64> {
        self.metadata().ok().map(|m| m.len())
    }
}
