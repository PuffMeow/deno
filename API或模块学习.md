## cli-> main 入口中

### std::env::current_exe

返回当前运行的可执行文件的完整文件系统路径，比如运行 `cargo run -- --filename index.js`
这时候就会返回 cli 命令行的完整系统路径。
[std::env::current_exe](https://doc.rust-lang.org/std/env/fn.current_exe.html)

### eszip

可以下载 JavaScript 和 TypeScript 模块图，并将它们存储在本地一个特殊的 zip 文件中
代表作是 `deno_graph::ModuleGraph`
