# AGENTS.md

本文件给在本仓库中工作的 AI 编码助手使用。项目概况见 [README.md](README.md)。

## 项目概况

- Rust 核心的密码算法库。规划的算法包括 AES、SM4、SM2、通用椭圆曲线、FourQ、Paillier、PSI、PIR。
- 已实现：AES 和 SM4 的 GCM / CBC / CTR 模式（`crates/cipher-sym`）。
- 当前只做 Python 接口（PyO3，`bindings/python`）。Go 和 Java 暂不实现，不要创建 `cipher-ffi` 或其他语言的绑定，除非维护者明确要求。
- 目标平台：Linux / macOS，x86_64 / arm64。

## Python 3.8 兼容

Python 包必须支持 Python 3.8：
- PyO3 固定在 0.29.x，启用 `abi3-py38` feature。0.29 是最后一个支持 3.8 的版本，0.30 已删除 `abi3-py38`，不要升级。
- Python 代码不能用 3.9+ 语法：不用 `X | Y` 类型联合、`list[int]` 这类内置泛型、`match` 语句，用 `typing.Optional` / `Union` / `List`。
- 改动后在 3.8 解释器上跑测试。可以用 `uv python install 3.8` 安装。

## 常用命令

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# Python（在 venv 中）
maturin develop --release -m bindings/python/Cargo.toml
pytest bindings/python/tests
maturin build --release -m bindings/python/Cargo.toml -o dist   # 产出 cp38-abi3 wheel
```

`.cargo/config.toml` 为 macOS 设置了 `-undefined dynamic_lookup`，这样直接用 `cargo build` 也能链接 Python 扩展。

提交前必须保证 `fmt`、`clippy`、`cargo test`、`pytest` 全部通过。

## Python 绑定约定

- Rust 扩展模块是 `cipher_algorithm._native`，只接受 `bytes`，没有默认参数。
- 公开 API 放在 `python/cipher_algorithm/<算法>.py`，负责默认参数、文档字符串，并通过 `_util.as_bytes` 规范化输入。不要用 `bytes(x)` 转换，因为 `bytes(16)` 会生成 16 个零字节。
- 新增原生函数时要同步更新 `_native.pyi`。
- 原生函数用 `py.detach` 释放 GIL。
- 所有失败都抛 `CipherError`（`ValueError` 的子类）。类型错误抛 `TypeError`。
- `aes` 和 `sm4` 保持相同的函数名和参数顺序。新增对称算法时沿用这套接口。

## 架构约定

依赖方向只能从上到下：bindings → cipher-ffi → 协议层（psi、pir）→ 原语层（sym、ecc、he）→ cipher-core。原语层之间不要相互依赖，需要共享的东西放进 cipher-core。

协议层采用 sans-IO 设计：
- 协议的每一方都是一个状态机，接收消息字节，输出下一条消息字节。
- 不要在库内引入网络、线程池或异步运行时。
- 协议消息使用带 magic 和版本号的二进制格式，修改格式时要升级版本号。

ECC：
- 所有曲线都实现 `cipher-ecc` 中的 `Group` trait。
- ECDH-PSI 等协议对 `Group` 泛型，不要针对某一条曲线写死。

## C ABI 规则（cipher-ffi，将来给 Go / Java 用）

- 对象用不透明指针，例如 `cipher_xxx_t*`，成对提供 `cipher_xxx_new` 和 `cipher_xxx_free`。
- 数据只用 `const uint8_t* ptr + size_t len` 传递。库分配的输出用 `cipher_buf_free` 释放。
- 函数返回 `int` 错误码，错误详情通过 `cipher_last_error_message()` 获取。
- 不跨边界传递 Rust 结构体、`String`、`Vec` 或回调。
- 每个导出函数都要用 `catch_unwind` 包住，panic 不能越过 FFI 边界。
- 所有指针参数都要做空指针和长度检查。
- 头文件由 cbindgen 生成，不要手改。
- 批量数据（如 PSI 集合）一次传入，避免对每个元素单独调用一次 FFI。
- 已发布的 C 函数签名不能改，只能新增函数。

## 密码学安全规则

- 不要自己实现分组密码、哈希、曲线运算等底层原语，优先使用 RustCrypto、curve25519-dalek 等审计过的库。FourQ 通过 `cc` 封装微软 FourQlib。
- 处理秘密数据的代码必须常数时间。不要按秘密值做分支、查表或提前返回，比较用 `subtle`。
- 密钥和中间秘密值用 `zeroize` 清理。
- 随机数只用 CSPRNG（`OsRng` 或 `rand_core::CryptoRngCore`）。生产代码中禁止固定种子；测试中允许。
- 外部输入（消息、密钥、密文）一律视为不可信，解析时校验长度、点是否在曲线上、标量范围等。
- 错误信息中不要包含密钥或明文。
- 新增 `unsafe` 代码必须写 `// SAFETY:` 注释说明理由，并尽量只放在 cipher-ffi 中。

## 测试要求

- 每个原语都必须通过官方测试向量：AES 用 NIST CAVP，SM2 用 GB/T 32918，SM4 用 GB/T 32907，曲线用对应的 RFC 向量。
- 协议要有端到端测试，覆盖空集合、无交集、全交集、大集合等场景。
- 标准向量放在 `crates/<crate>/tests/vectors.rs`，注明出处（标准编号和附录）。
- Python 测试要和 OpenSSL（`cryptography` 包）逐字节对比，见 `bindings/python/tests/test_openssl_compat.py`。没装 `cryptography` 时这些测试自动跳过。
- 跨语言一致性：相同输入在各语言上的输出必须逐字节一致。
- 修改 FFI 或消息解析代码时，同步补充 cargo-fuzz 目标。

## 依赖管理

- 新增依赖使用精确版本，并说明选择理由。
- 注意许可证：GMP（`rug`）是 LGPL，是否允许引入还没确定，引入前需先与维护者确认。

## 待定事项

修改相关代码前，先与维护者确认：
- Java 最低 JDK 版本，这决定使用 JNI 还是 FFM（Java 绑定启动时再定）。
- Paillier 的大数后端：`rug`（GMP）还是 `num-bigint` / `crypto-bigint`。
- 项目许可证。
