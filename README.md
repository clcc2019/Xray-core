# Xray-core Performance Fork

基于 [Xray-core](https://github.com/XTLS/Xray-core) 的性能优化分支。

## 性能优化

本分支专注于以下性能优化：

- **缓冲区管理优化**: Buffer 结构体池化，减少 GC 压力
- **内存池优化**: 多级内存池设计，减少内存分配
- **传输管道优化**: 改进的读写信号机制
- **连接处理优化**: 更高效的连接调度

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
