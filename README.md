# Hikari-LLVM19

**enable-strcry在rust中可能存在问题，其他自行测试**

> Warning: 仅在mac arm64上编译通过，未经过完全测试

混淆插件提取自 [Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15) By 61bcdefg 项目。

## 编译

### 环境
Macos 15.2
LLVM 19.1.7

```bash
cmake -G "Ninja" -S . -B ./build \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DLT_LLVM_INSTALL_DIR=/opt/homebrew/opt/llvm@19
```
**注意要将 LT_LLVM_INSTALL_DIR 换为自己，CMake里硬编码了，也要替换**

## rust 动态加载

动态加载 llvm pass 插件需切换到 nightly 通道

```bash
rustup toolchain install nightly
```

生成一个示例项目，通过 `-Zllvm-plugins` 参数加载 pass 插件，并通过 `-Cpasses` 参数指定混淆开关：

```bash
cargo new helloworld --bin
cd helloworld
cargo +nightly rustc --release -- -Zllvm-plugins="path/to/libHikari.dylib" -Cpasses="hikari(enable-fco,enable-strcry)..."
```

## opt 动态加载

```bash
# 使用 clang 编译源代码并生成 IR
clang -emit-llvm -c input.c -o input.bc

# 使用 opt 工具加载和运行自定义 Pass
opt -load-pass-plugin="path/to/libHikari.dylib" --passes="hikari(enable-fco,enable-strcry)..." input.bc -o output.bc

# 将 IR 文件编译为目标文件
llc -filetype=obj output.bc -o output.o

# 链接目标文件生成可执行文件
clang output.o -o output
```

## 感谢
[Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15) By 61bcdefg

[ollvm-rust](https://github.com/0xlane/ollvm-rust) By REinject
