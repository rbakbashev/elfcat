# elfcat 完整指南

## 目录

1. [简介](#简介)
2. [安装](#安装)
3. [快速入门](#快速入门)
4. [ELF 基础](#elf 基础)
5. [可视化详解](#可视化详解)
6. [高级用法](#高级用法)
7. [使用场景](#使用场景)
8. [故障排除](#故障排除)
9. [完整示例](#完整示例)
10. [相关工具](#相关工具)

---

## 简介

**elfcat** 是一个 ELF 二进制文件可视化工具，可将 ELF 可执行文件转换为交互式 HTML 文件。

### 主要功能

- 📊 **可视化展示** - 将二进制结构转换为直观的 HTML 图表
- 🔍 **结构分析** - 清晰展示 ELF 头、程序头、段头表
- 📚 **教育用途** - 学习 ELF 格式的理想工具
- 🔧 **逆向工程** - 快速了解二进制文件结构
- 🎨 **交互体验** - 可缩放、可搜索的 HTML 输出
- ⚡ **快速生成** - 秒级生成可视化文件

### 支持的 ELF 类型

| 类型 | 说明 | 示例 |
|------|------|------|
| **ET_REL** | 可重定位文件 | `.o` 目标文件 |
| **ET_EXEC** | 可执行文件 | `/bin/ls` |
| **ET_DYN** | 共享对象 | `.so` 库，PIE 可执行文件 |
| **ET_CORE** | 核心文件 | 崩溃转储 |

### 架构支持

- ✅ x86 (32-bit)
- ✅ x86-64 (AMD64)
- ✅ ARM (32-bit)
- ✅ AArch64 (ARM64)
- ✅ RISC-V
- ✅ MIPS
- ✅ PowerPC
- ✅ 其他 ELF 架构

---

## 安装

### 从 Crates.io (推荐)

```bash
# 安装 Rust (如果未安装)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装 elfcat
cargo install elfcat

# 验证安装
elfcat --version

# 查看帮助
elfcat --help

# 卸载
cargo uninstall elfcat
```

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/rbakbashev/elfcat
cd elfcat

# 编译 Release 版本
cargo build --release

# 二进制位置
./target/release/elfcat

# (可选) 安装到系统
sudo cp target/release/elfcat /usr/local/bin/

# 验证
elfcat --version
```

**编译要求**:
- Rust 1.60+
- 1GB+ 可用内存
- 约 5 分钟编译时间

### 预编译二进制

1. 访问 [GitHub Releases](https://github.com/rbakbashev/elfcat/releases)
2. 下载对应平台的二进制文件
3. 解压并添加到 PATH

```bash
# Linux
wget https://github.com/rbakbashev/elfcat/releases/latest/download/elfcat-x86_64-unknown-linux-gnu.tar.gz
tar -xzf elfcat-*.tar.gz
sudo mv elfcat /usr/local/bin/

# macOS
wget https://github.com/rbakbashev/elfcat/releases/latest/download/elfcat-x86_64-apple-darwin.tar.gz
tar -xzf elfcat-*.tar.gz
sudo mv elfcat /usr/local/bin/

# Windows
# 下载 .zip 文件，解压，添加到 PATH
```

### 包管理器

#### Arch Linux (AUR)

```bash
# 使用 yay
yay -S elfcat

# 使用 paru
paru -S elfcat
```

#### Nix/NixOS

```nix
# configuration.nix 或 home.nix
environment.systemPackages = [
  (pkgs.rustPlatform.buildRustPackage {
    pname = "elfcat";
    version = "latest";
    src = pkgs.fetchFromGitHub {
      owner = "rbakbashev";
      repo = "elfcat";
      rev = "v0.1.5";
      sha256 = "...";
    };
    cargoSha256 = "...";
  })
];
```

---

## 快速入门

### 基本用法

```bash
# 可视化 ELF 文件
elfcat /bin/ls

# 输出到指定文件
elfcat /bin/ls -o ls-visualization.html

# 在浏览器中打开
firefox ls-visualization.html
# 或
google-chrome ls-visualization.html
```

### 输出示例

运行后生成的 HTML 文件包含：

```
┌─────────────────────────────────────────────────────────┐
│                    ELF Visualization                     │
│                    /bin/ls                               │
├─────────────────────────────────────────────────────────┤
│  ELF Header                                             │
│  ├─ Magic: 7f 45 4c 46                                  │
│  ├─ Class: ELF64                                        │
│  ├─ Data: Little Endian                                 │
│  ├─ Version: 1                                          │
│  ├─ OS/ABI: UNIX System V                               │
│  ├─ Type: DYN (Shared object file)                      │
│  ├─ Machine: Advanced Micro Devices X86-64              │
│  └─ Entry Point: 0x6b10                                 │
│                                                         │
│  Program Headers                                        │
│  ├─ PHDR (0x40 - 0x1c8)                                 │
│  ├─ INTERP (0x1c8 - 0x1e9)                              │
│  ├─ LOAD (0x0 - 0x3a28)  [R E]                          │
│  ├─ LOAD (0x3e58 - 0x5a88) [R W]                        │
│  └─ ...                                                 │
│                                                         │
│  Section Headers                                        │
│  ├─ .text (0x1060 - 0x3359)  [R X]                      │
│  ├─ .rodata (0x3360 - 0x3a27) [R]                       │
│  ├─ .data (0x4e60 - 0x4f08)  [R W]                      │
│  └─ ...                                                 │
└─────────────────────────────────────────────────────────┘
```

### 命令行选项

```bash
elfcat --help

# 可用选项:
#   <input>        输入的 ELF 文件路径
#   -o, --output   输出 HTML 文件路径 (默认：<input>.html)
#   -h, --help     显示帮助信息
#   -v, --version  显示版本信息
```

---

## ELF 基础

### ELF 文件结构

```
┌─────────────────────────┐
│      ELF Header         │  ← 文件开头，固定 52/64 字节
├─────────────────────────┤
│   Program Header Table  │  ← 程序头表 (可选)
├─────────────────────────┤
│                         │
│      Code Segment       │  ← 代码段 (.text)
│      Data Segment       │  ← 数据段 (.data, .rodata)
│      Other Segments     │
│                         │
├─────────────────────────┤
│   Section Header Table  │  ← 段头表
└─────────────────────────┘
```

### ELF Header 详解

| 字段 | 大小 (64 位) | 说明 |
|------|-------------|------|
| **e_ident** | 16 字节 | ELF 魔数和元数据 |
| **e_type** | 2 字节 | 文件类型 (EXEC, DYN, REL) |
| **e_machine** | 2 字节 | 目标架构 (x86, ARM, etc.) |
| **e_version** | 4 字节 | ELF 版本 |
| **e_entry** | 8 字节 | 程序入口点地址 |
| **e_phoff** | 8 字节 | 程序头表偏移 |
| **e_shoff** | 8 字节 | 段头表偏移 |
| **e_flags** | 4 字节 | 处理器特定标志 |
| **e_ehsize** | 2 字节 | ELF 头大小 |
| **e_phentsize** | 2 字节 | 程序头表项大小 |
| **e_phnum** | 2 字节 | 程序头表项数量 |
| **e_shentsize** | 2 字节 | 段头表项大小 |
| **e_shnum** | 2 字节 | 段头表项数量 |
| **e_shstrndx** | 2 字节 | 段名字符串表索引 |

### Program Header (程序头)

| 类型 | 说明 |
|------|------|
| **PT_NULL** | 未使用的表项 |
| **PT_LOAD** | 可加载段 |
| **PT_DYNAMIC** | 动态链接信息 |
| **PT_INTERP** | 解释器路径 |
| **PT_NOTE** | 辅助信息 |
| **PT_SHLIB** | 保留 |
| **PT_PHDR** | 程序头表本身 |
| **PT_GNU_STACK** | 栈权限 |
| **PT_GNU_RELRO** | 只读重定位 |

### Section Header (段头)

常见段类型：

| 段名 | 说明 | 权限 |
|------|------|------|
| **.text** | 可执行代码 | R-X |
| **.data** | 已初始化数据 | RW- |
| **.rodata** | 只读数据 | R-- |
| **.bss** | 未初始化数据 | RW- |
| **.symtab** | 符号表 | R-- |
| **.strtab** | 字符串表 | R-- |
| **.dynsym** | 动态符号 | R-- |
| **.plt** | 过程链接表 | R-X |
| **.got** | 全局偏移表 | RW- |
| **.debug_*** | 调试信息 | R-- |

---

## 可视化详解

### HTML 输出结构

生成的 HTML 文件包含：

1. **ELF Header 视图**
   - 魔数验证
   - 文件类型标识
   - 架构信息
   - 入口点地址

2. **Program Headers 视图**
   - 段类型
   - 虚拟地址
   - 物理地址
   - 文件大小
   - 内存大小
   - 权限标志

3. **Section Headers 视图**
   - 段名
   - 段类型
   - 地址
   - 偏移
   - 大小
   - 权限

4. **十六进制查看器**
   - 原始二进制数据
   - ASCII 对照
   - 地址导航

### 交互功能

- 🔍 **搜索** - 搜索段名、符号名
- 📍 **导航** - 快速跳转到特定段
- 🔗 **链接** - 点击跳转到相关段
- 📊 **统计** - 文件大小、段数量统计
- 🎨 **高亮** - 不同类型段颜色区分

### 颜色编码

| 颜色 | 含义 |
|------|------|
| 🔵 蓝色 | 代码段 (.text) |
| 🟢 绿色 | 数据段 (.data) |
| 🟡 黄色 | 只读段 (.rodata) |
| 🔴 红色 | 特殊段 (.plt, .got) |
| 🟣 紫色 | 调试段 (.debug_*) |
| ⚪ 灰色 | 其他段 |

---

## 高级用法

### 分析不同类型的二进制文件

#### 系统二进制文件

```bash
# 分析 shell
elfcat /bin/bash -o bash.html

# 分析核心工具
elfcat /bin/ls -o ls.html
elfcat /bin/cat -o cat.html
```

#### 共享库

```bash
# 分析 C 库
elfcat /lib/x86_64-linux-gnu/libc.so.6 -o libc.html

# 分析 C++ 库
elfcat /lib/x86_64-linux-gnu/libstdc++.so.6 -o libstdc++.html
```

#### 内核模块

```bash
# 分析内核模块
elfcat /lib/modules/$(uname -r)/kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko -o e1000e.html
```

#### 自定义编译的程序

```bash
# 编译程序
gcc -o myapp myapp.c

# 分析
elfcat myapp -o myapp.html

# 对比不同优化级别
gcc -O0 myapp.c -o myapp-O0
gcc -O2 myapp.c -o myapp-O2
gcc -O3 myapp.c -o myapp-O3

elfcat myapp-O0 -o O0.html
elfcat myapp-O2 -o O2.html
elfcat myapp-O3 -o O3.html
```

### 安全分析

#### 检查 RELRO

```bash
elfcat binary -o binary.html

# 在 HTML 中查找:
# PT_GNU_RELRO - 表示有 RELRO 保护
# .got 段权限 - RW (Partial RELRO) 或 R (Full RELRO)
```

**RELRO 级别**:
- **No RELRO** - 无保护
- **Partial RELRO** - .got 可写
- **Full RELRO** - .got 只读 (最安全)

#### 检查 PIE (位置无关可执行文件)

```bash
elfcat binary -o binary.html

# 在 ELF Header 中查看:
# Type: EXEC - 非 PIE
# Type: DYN - PIE  enabled
```

#### 检查栈保护

```bash
elfcat binary -o binary.html

# 查找 PT_GNU_STACK:
# RW-  - 栈可执行 (不安全)
# RW   - 栈不可执行 (安全)
```

### 性能分析

#### 识别大段

```bash
elfcat large_binary -o large_binary.html

# 在 HTML 中查看各段大小
# 识别占用空间最大的段
# 分析是否可以优化
```

#### 调试符号分析

```bash
# 编译带调试符号
gcc -g myapp.c -o myapp-debug

# 编译不带调试符号
gcc -s myapp.c -o myapp

# 对比
elfcat myapp-debug -o debug.html
elfcat myapp -o stripped.html

# 调试符号通常占用大量空间
```

---

## 使用场景

### 1. 逆向工程

```bash
# 分析未知二进制
elfcat suspicious_binary -o analysis.html

# 结合其他工具
rabin2 -I suspicious_binary  # 获取 ELF 信息
elfcat suspicious_binary     # 可视化结构
```

**工作流**:
1. elfcat 快速了解结构
2. radare2/Ghidra 深入分析
3. 对照 ELF 可视化定位关键段

### 2. 教育教学

```bash
# 创建教学材料
elfcat /bin/ls -o example-executable.html
elfcat hello.o -o object-file.html
elfcat libc.so.6 -o shared-library.html
```

**教学要点**:
- ELF 文件格式
- 链接过程
- 加载过程
- 段与段的区别

### 3. 编译器开发

```bash
# 分析编译器输出
gcc -c file1.c -o file1.o
gcc -c file2.c -o file2.o
ld file1.o file2.o -o program

elfcat file1.o -o file1.html
elfcat file2.o -o file2.html
elfcat program -o program.html
```

**验证内容**:
- 符号是否正确导出
- 段是否正确合并
- 重定位是否正确

### 4. 安全审计

```bash
# 审计二进制安全性
for binary in /usr/bin/*; do
    elfcat "$binary" -o "/tmp/security-audit/$(basename $binary).html"
done

# 批量检查:
# - RELRO 状态
# - PIE 状态
# - 栈执行权限
```

### 5. 嵌入式开发

```bash
# 分析嵌入式二进制
elfcat firmware.elf -o firmware.html

# 检查:
# - 代码段大小 (是否符合内存限制)
# - 数据段布局
# - 入口点配置
```

---

## 故障排除

### 常见问题

#### 1. "Not an ELF file"

**原因**: 文件不是 ELF 格式

**解决**:
```bash
# 验证文件类型
file binary

# 检查文件内容
hexdump -C binary | head

# ELF 文件应以 7f 45 4c 46 开头
```

#### 2. "Permission denied"

**原因**: 无读取权限

**解决**:
```bash
# 添加读权限
chmod +r binary

# 或使用 sudo
sudo elfcat /bin/su -o su.html
```

#### 3. "File too large"

**原因**: 文件过大，HTML 生成慢

**解决**:
```bash
# 考虑只分析关键段
readelf -S large_binary | head

# 或使用专业工具
readelf -a large_binary > analysis.txt
```

#### 4. HTML 文件无法打开

**原因**: 浏览器安全限制

**解决**:
```bash
# 使用本地服务器
python3 -m http.server 8000
# 访问 http://localhost:8000/output.html

# 或使用 Firefox
firefox --no-remote output.html
```

#### 5. 中文显示乱码

**原因**: 编码问题

**解决**:
```bash
# 确保终端 UTF-8
export LANG=en_US.UTF-8

# HTML 文件用 UTF-8 打开
# 现代浏览器自动处理
```

#### 6. 输出 HTML 过大

**原因**: 二进制文件大

**解决**:
```bash
# 压缩 HTML
gzip -k output.html

# 或使用在线查看器
# 上传到安全环境查看
```

### 性能优化

#### 加快生成速度

```bash
# 使用 Release 版本
cargo build --release

# 避免分析超大文件 (>500MB)
# 使用 readelf 替代
```

#### 减少 HTML 大小

```bash
# 压缩输出
gzip output.html

# 或使用精简模式 (如果支持)
elfcat binary --minimal -o output.html
```

---

## 完整示例

### 示例 1: Hello World 分析

```bash
# 创建简单程序
cat > hello.c << 'EOF'
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
EOF

# 编译
gcc -o hello hello.c

# 可视化
elfcat hello -o hello.html

# 在浏览器中查看
firefox hello.html
```

**学习要点**:
- .text 段包含 main 函数
- .rodata 包含字符串常量
- .plt 包含 printf 调用

### 示例 2: 多文件项目

```bash
# 创建多文件项目
cat > main.c << 'EOF'
extern void helper();
int main() { helper(); return 0; }
EOF

cat > helper.c << 'EOF'
#include <stdio.h>
void helper() { printf("Helper!\n"); }
EOF

# 编译目标文件
gcc -c main.c -o main.o
gcc -c helper.c -o helper.o

# 可视化目标文件
elfcat main.o -o main-object.html
elfcat helper.o -o helper-object.html

# 链接
gcc main.o helper.o -o program

# 可视化可执行文件
elfcat program -o program.html
```

**学习要点**:
- 目标文件的符号表
- 链接后的段合并
- 外部符号解析

### 示例 3: 优化级别对比

```bash
#!/bin/bash

# 创建测试程序
cat > test.c << 'EOF'
int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n-1) + fibonacci(n-2);
}

int main() {
    return fibonacci(10);
}
EOF

# 不同优化级别编译
gcc -O0 test.c -o test-O0
gcc -O1 test.c -o test-O1
gcc -O2 test.c -o test-O2
gcc -O3 test.c -o test-O3

# 可视化
elfcat test-O0 -o O0.html
elfcat test-O1 -o O1.html
elfcat test-O2 -o O2.html
elfcat test-O3 -o O3.html

# 对比文件大小
ls -lh test-O*
```

**学习要点**:
- 优化对代码大小的影响
- 内联优化
- 循环展开

### 示例 4: 安全性检查脚本

```bash
#!/bin/bash
# security-check.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

BINARY=$1
OUTPUT="security-$(basename $BINARY).html"

echo "Analyzing security features of $BINARY..."

# 生成可视化
elfcat "$BINARY" -o "$OUTPUT"

# 检查关键特性
echo ""
echo "=== Security Features ==="

# PIE check
if readelf -h "$BINARY" | grep -q "DYN"; then
    echo "✅ PIE: Enabled"
else
    echo "❌ PIE: Disabled"
fi

# RELRO check
if readelf -l "$BINARY" | grep -q "GNU_RELRO"; then
    if readelf -d "$BINARY" | grep -q "BIND_NOW"; then
        echo "✅ RELRO: Full"
    else
        echo "⚠️  RELRO: Partial"
    fi
else
    echo "❌ RELRO: None"
fi

# Stack check
if readelf -l "$BINARY" | grep "GNU_STACK" | grep -q "RWE"; then
    echo "❌ Stack: Executable (Dangerous!)"
else
    echo "✅ Stack: Non-executable"
fi

echo ""
echo "Full visualization: $OUTPUT"
```

### 示例 5: 批量分析脚本

```bash
#!/bin/bash
# batch-analyze.sh

OUTPUT_DIR="elf-analysis"
mkdir -p "$OUTPUT_DIR"

echo "Analyzing all binaries in /usr/bin..."

count=0
for binary in /usr/bin/*; do
    if file "$binary" | grep -q "ELF"; then
        elfcat "$binary" -o "$OUTPUT_DIR/$(basename $binary).html"
        ((count++))
        echo "[$count] $(basename $binary)"
    fi
done

echo ""
echo "Analysis complete!"
echo "Total: $count binaries"
echo "Output: $OUTPUT_DIR/"
```

---

## 相关工具

### ELF 分析工具

| 工具 | 用途 |
|------|------|
| **readelf** | 详细 ELF 信息 |
| **objdump** | 反汇编、段信息 |
| **file** | 文件类型识别 |
| **nm** | 符号表查看 |
| **strings** | 提取字符串 |
| **ldd** | 依赖库查看 |

### 逆向工程工具

| 工具 | 用途 |
|------|------|
| **radare2** | 逆向工程框架 |
| **Ghidra** | NSA 逆向工具 |
| **IDA Pro** | 商业逆向工具 |
| **Binary Ninja** | 商业逆向工具 |
| **Hopper** | macOS 逆向工具 |

### 学习资源

- **ELF Specification**: https://refspecs.linuxfoundation.org/elf/elf.pdf
- **LSE ELF 教程**: https://linuxsecurity.expert/tutorials/elf-file-format
- **逆向工程入门**: https://beginners.re/

---

## 社区

- **Repository**: https://github.com/rbakbashev/elfcat
- **Issues**: https://github.com/rbakbashev/elfcat/issues
- **Changelog**: https://github.com/rbakbashev/elfcat/blob/master/changelog.md

## 性能基准

### 生成速度

| 文件大小 | 生成时间 | HTML 大小 |
|---------|---------|---------|
| 100KB | <0.5s | ~500KB |
| 1MB | <2s | ~2MB |
| 10MB | <10s | ~10MB |
| 100MB | <60s | ~50MB |

### 内存使用

| 阶段 | 内存占用 |
|------|---------|
| 解析 ELF | ~10MB |
| 生成 HTML | ~50MB |
| 峰值使用 | ~100MB |

### 浏览器渲染

| 浏览器 | 渲染时间 | 交互流畅度 |
|--------|---------|-----------|
| Chrome | <1s | ✅ 优秀 |
| Firefox | <1s | ✅ 优秀 |
| Safari | <2s | ✅ 良好 |
| Edge | <1s | ✅ 优秀 |

## 常见问题解答

### Q: elfcat 与 readelf 相比如何？

**A**: 
- **readelf**: 详细文本输出，适合脚本处理
- **elfcat**: 可视化 HTML，适合学习和展示
- 两者互补，不是替代关系

### Q: 支持哪些 ELF 格式？

**A**:
- ✅ ELF32 (32 位)
- ✅ ELF64 (64 位)
- ✅ 所有主流架构 (x86, ARM, RISC-V, etc.)
- ⚠️ 某些特殊格式可能不支持

### Q: 可以分析 Windows PE 文件吗？

**A**:
- ❌ 不支持，PE 是不同格式
- 使用 PE-bear 或 CFF Explorer 分析 PE
- elfcat 仅支持 ELF (Linux/Unix)

### Q: 如何分享可视化结果？

**A**:
1. 生成 HTML 文件
2. 直接发送 HTML (包含所有数据)
3. 或部署到 Web 服务器
4. 或使用 GitHub Pages

### Q: HTML 文件太大怎么办？

**A**:
```bash
# 压缩 HTML
gzip -k output.html
# 生成 output.html.gz

# 或使用在线工具
# 上传到安全的内部服务器
```

### Q: 支持动态链接库分析吗？

**A**:
- ✅ 支持 .so 文件分析
- 显示导出/导入符号
- 显示依赖关系

### Q: 可以批量分析吗？

**A**:
```bash
#!/bin/bash
for binary in /usr/bin/*; do
    elfcat "$binary" -o "analysis/$(basename $binary).html"
done
```

### Q: 支持内核模块分析吗？

**A**:
- ✅ 支持 .ko 文件
- 显示模块信息
- 显示段和符号

### Q: 如何验证 ELF 完整性？

**A**:
```bash
# 使用 elfcat 可视化检查
elfcat binary -o check.html

# 结合其他工具
readelf -h binary  # 验证头部
sha256sum binary   # 验证哈希
```

### Q: 支持调试信息分析吗？

**A**:
- ✅ 显示 .debug_* 段
- 但不解析 DWARF 内容
- 使用 readelf --debug-dump 查看详细调试信息

### Q: 可以自定义 HTML 样式吗？

**A**:
- 目前不支持自定义
- 可修改源码后重新编译
- 欢迎贡献此功能

### Q: 支持中文显示吗？

**A**:
- ✅ HTML 使用 UTF-8 编码
- ✅ 支持所有 Unicode 字符
- 段名和符号名正确显示

---

*Community contribution - unofficial comprehensive guide*  
*Last updated: 2026-04-10*  
*Word count: ~16KB*
