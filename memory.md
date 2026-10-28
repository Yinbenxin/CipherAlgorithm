# memory.md

开发过程中踩过的坑和解决办法。

## 构建工具 maturin / zig 下载卡住（2026-10-28）

现象：构建 Linux wheel 前要先装 `maturin==1.15.0` 和 `ziglang==0.13.0`。`pip install` 长时间没有进度，看起来像卡死了。

原因：本地代理 `127.0.0.1:7897` 访问 PyPI 很慢，实测下载 `files.pythonhosted.org` 只有约 28 KB/s。`ziglang` 的 wheel 有几十 MB，按这个速度要很久才能装完。

解决：pip 不走代理，改用清华镜像。实测直连镜像约 200 KB/s，两个包 2 分钟装完。

```bash
unset https_proxy http_proxy all_proxy
python3 -m venv .venv-tools
.venv-tools/bin/pip install -i https://pypi.tuna.tsinghua.edu.cn/simple "maturin==1.15.0" "ziglang==0.13.0"
```

装好后，在 macOS 上交叉编译 Linux aarch64 wheel（本机没有 Docker，用 zig 做链接器）：

```bash
export PATH="$PWD/.venv-tools/bin:$PATH"
maturin build --release -m bindings/python/Cargo.toml \
  --target aarch64-unknown-linux-gnu --zig --compatibility manylinux2014 -o dist
```

经验：
- 下载一直没有进度时，先用 curl 测速（`curl -o /dev/null -w "%{speed_download}"`），确认是网速问题，再决定换镜像还是换代理。
- PyPI 用清华镜像直连。crates.io 仍然走代理，`cargo fetch` 走代理正常。

## 相关的未解决问题

- `rustup target add x86_64-unknown-linux-gnu` 同样卡住没有完成，所以 Linux x86_64 wheel 还没在本地构建。可以先在 CI（`.github/workflows/wheels.yml`）上构建，或者给 rustup 配置国内镜像（`RUSTUP_DIST_SERVER`）后重试。
