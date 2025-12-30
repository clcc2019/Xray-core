# Xray-core Performance Fork

基于 [Xray-core](https://github.com/XTLS/Xray-core) 的性能优化分支。

## 性能优化

本分支专注于以下性能优化：

### 内存管理优化

- **MultiBuffer 切片池化** (`common/buf/multi_buffer.go`)
  - 新增 `multiBufferPool` 池化 MultiBuffer 切片
  - 新增 `GetMultiBuffer()` / `PutMultiBuffer()` 接口
  - 新增 `ReleaseMultiAndReturn()` 释放并回收到池
  - 减少高吞吐场景下的切片分配

- **Buffer 结构体池化** (`common/buf/buffer.go`)
  - 已有的 `bufferPool` 池化 Buffer 结构体
  - 已有的 `bytespool` 多级内存池 (2KB/8KB/32KB/128KB)

### 数据传输优化

- **Copy 函数快速路径** (`common/buf/copy.go`)
  - 新增 `copyFast()` 无 handler 快速路径
  - 无 option 时跳过 handler 分配和迭代
  - 减少热路径上的开销

### 管道传输优化

- **Pipe 无锁长度查询** (`transport/pipe/impl.go`)
  - 新增 `dataLen` 原子变量缓存数据长度
  - `Len()` 和 `hasData()` 无需获取锁
  - 减少锁竞争，提高并发性能

### 信号通知优化

- **Notifier 池化** (`common/signal/notifier.go`)
  - 新增 `notifierPool` 池化 Notifier 实例
  - 新增 `Release()` 方法回收到池
  - 减少频繁创建销毁的开销

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## 文档

[Project X 官方文档](https://xtls.github.io)

## 编译

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### 可复现构建

确保使用相同的 Go 版本，并设置 git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

## Credits

- 基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- 第三方依赖详见 [go.mod](https://github.com/XTLS/Xray-core/blob/main/go.mod)
