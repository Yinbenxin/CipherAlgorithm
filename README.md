# CipherAlgorithm

CipherAlgorithm 是一个面向工业落地的密码算法与隐私计算库。核心用 Rust 实现，目前提供 Python 接口，Go 和 Java 接口后续规划。

> 状态：开发中，尚未发布到 PyPI。接口在 1.0 之前可能调整。

## 支持的算法

| 类别 | 算法 | 状态 |
|---|---|---|
| 对称加密 | AES-128/192/256（GCM / CBC / CTR） | 已实现 |
| 对称加密 | SM4（GCM / CBC / CTR） | 已实现 |
| 公钥密码 | SM2（签名、加密、密钥交换） | 规划中 |
| 椭圆曲线 | P-256、secp256k1、Curve25519 / Ristretto255、FourQ | 规划中 |
| 同态加密 | Paillier | 规划中 |
| 隐私求交 | ECDH-PSI，后续支持 OT 类 PSI（KKRT / RR22）、PSI-CA | 规划中 |
| 隐匿查询 | PIR | 规划中 |

## 支持平台

- Python 3.8 及以上。发布的是 abi3 wheel，一个 wheel 可用于所有 3.8+ 版本。
- 操作系统：Linux（glibc，manylinux）、macOS
- 架构：x86_64、arm64

## 使用示例

```python
import os
from cipher_algorithm import CipherError, aes, sm4

key = os.urandom(32)          # 16 / 24 / 32 字节分别对应 AES-128 / 192 / 256
nonce = os.urandom(12)        # GCM nonce，同一个密钥下绝不能重复

ct = aes.gcm_encrypt(key, nonce, b"hello", aad=b"header")   # 返回 密文 || 16 字节 tag
pt = aes.gcm_decrypt(key, nonce, ct, aad=b"header")

try:
    aes.gcm_decrypt(key, nonce, ct, aad=b"wrong")
except CipherError:
    print("认证失败")

sm4_key = os.urandom(16)
iv = os.urandom(16)
ct = sm4.cbc_encrypt(sm4_key, iv, b"hello")   # PKCS#7 填充
ct = sm4.ctr_encrypt(sm4_key, iv, b"hello")   # 128 位大端计数器
```

`aes` 和 `sm4` 模块提供同样的六个函数：

| 函数 | nonce / IV | 说明 |
|---|---|---|
| `gcm_encrypt(key, nonce, plaintext, aad=b"")` | 12 字节 | 输出 `密文 \|\| 16 字节 tag` |
| `gcm_decrypt(key, nonce, ciphertext, aad=b"")` | 12 字节 | tag 校验失败时抛 `CipherError` |
| `cbc_encrypt(key, iv, plaintext)` | 16 字节 | PKCS#7 填充 |
| `cbc_decrypt(key, iv, ciphertext)` | 16 字节 | 长度或填充错误时抛 `CipherError` |
| `ctr_encrypt(key, iv, plaintext)` | 16 字节 | `iv` 为初始计数器块 |
| `ctr_decrypt(key, iv, ciphertext)` | 16 字节 | 与 `ctr_encrypt` 相同 |

补充说明：
- 参数接受 `bytes`、`bytearray`、`memoryview`，返回值都是 `bytes`。
- `CipherError` 是 `ValueError` 的子类。
- 加解密期间会释放 GIL。
- CBC 和 CTR 不带认证，如果不是为了兼容已有系统，优先用 GCM。
- SM4-GCM 遵循 RFC 8998。
- 所有模式都与 OpenSSL 互通。

## 架构

```
┌──────────────┬──────────────┬───────────────┐
│ Python (PyO3)│ Go（规划中）  │ Java（规划中）  │  各语言封装
├──────────────┴──────┬───────┴───────────────┤
│                     │   C ABI（规划中）       │  句柄 + 字节缓冲区 + 错误码
├─────────────────────┴───────────────────────┤
│          协议层：PSI / PIR（sans-IO）           │
├─────────────────────────────────────────────┤
│  原语层：AES / SM4 / SM2 / Curves / FourQ /     │
│          Paillier                            │
├─────────────────────────────────────────────┤
│  基础层：错误类型、RNG、序列化、大数、zeroize       │
└─────────────────────────────────────────────┘
```

- 算法只在 Rust 中实现一次，各语言的计算结果完全一致。
- Python 直接通过 PyO3 绑定 Rust。Go 和 Java 将来共用同一套 C ABI。
- PSI、PIR 等交互式协议采用 sans-IO 设计。库只负责生成和处理消息字节，网络传输由调用方用 gRPC、HTTP、MQ 等自行实现。

## 目录结构

```
crates/
  cipher-core/   # 公共错误类型
  cipher-sym/    # AES、SM4（GCM / CBC / CTR）
bindings/
  python/        # PyO3 + maturin，Python 包 cipher_algorithm
```

后续计划新增：`cipher-ecc`（曲线、SM2、FourQ）、`cipher-he`（Paillier）、`cipher-psi`、`cipher-pir`，以及给 Go 和 Java 用的 `cipher-ffi`。

## 从源码构建

依赖：
- Rust 1.89 及以上（通过 rustup 安装）
- Python 3.8 及以上

```bash
cargo test --workspace                        # Rust 测试（含 NIST / GB/T / RFC 标准向量）

python3 -m venv .venv && . .venv/bin/activate
pip install maturin pytest cryptography
maturin develop --release -m bindings/python/Cargo.toml   # 编译并安装到当前 venv
pytest bindings/python/tests                  # Python 测试（含与 OpenSSL 的对比）

maturin build --release -m bindings/python/Cargo.toml -o dist   # 构建 wheel
```

## 安全说明

- 底层原语使用经过审计、常数时间实现的 RustCrypto 库（`aes`、`sm4`、`aes-gcm`、`cbc`、`ctr`），不自行实现分组密码。在支持的 CPU 上自动启用 AES-NI 和 ARMv8 AES 指令。
- 正确性用以下标准向量验证：NIST SP 800-38A（CBC / CTR）、McGrew–Viega GCM 测试向量、GB/T 32907-2016（SM4）、RFC 8998（SM4-GCM）。
- 本项目未经第三方安全审计。如业务涉及商用密码合规要求，请使用通过认证的密码模块。
- 发现安全问题请通过 GitHub 私下报告，不要公开提交 issue。

## 许可证

待定。
