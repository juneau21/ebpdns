//! **2.1.36（D 批）**：`ebpdns-server` 侧的统一 IO 入口。
//!
//! 实现本体只有一份，位于 [`ebpdns_fs`]（`crates/ebpdns-fs/src/lib.rs`）。本模块是
//! **薄 re-export**，让 server / bin 的调用点统一写 `crate::io_atomic::...`，同时避免
//! `ebpdns-cache`（不能反向依赖 server）与 server/bin 各留一套实现。
//!
//! 收敛前的 9 处原子写照旧按 [`WriteOptions`] 保留各自的 tmp 命名与失败清理策略；
//! 最终字节、`rename` 时机、目录 fsync 顺序均未改变。

pub use ebpdns_fs::{
    append_synced, atomic_write_bytes, atomic_write_bytes_opts, atomic_write_json,
    atomic_write_with, fsync_dir, fsync_dir_best_effort, TmpName, WriteOptions,
};
