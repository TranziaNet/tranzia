# 🌐 Tranzia

![Build](https://github.com/TranziaNet/tranzia/actions/workflows/build-publish.yml/badge.svg)
![Trivy Scan](https://github.com/TranziaNet/tranzia/actions/workflows/trivy-scan.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/TranziaNet/tranzia)](https://goreportcard.com/report/github.com/TranziaNet/tranzia)
![License](https://img.shields.io/github/license/TranziaNet/tranzia)
![Release](https://img.shields.io/github/v/release/TranziaNet/tranzia)
![Docker Pulls](https://img.shields.io/docker/pulls/ghcr.io/tranzianet/tranzia?logo=docker)

🚀 **Tranzia** is a modern, **all-in-one CLI toolkit for network testing and debugging**, aiming to unify the functionalities of tools like `nc`, `curl`, `openssl`, and `tcpdump` under a **single, extensible CLI**.

**⚠️ Note:** Tranzia is in **active early development** — expect frequent updates and evolving features.

---

## ✨ Why Tranzia?

Developers, SREs, and platform engineers rely on fragmented tools for day-to-day network diagnostics:
- `nc` for TCP connectivity
- `curl` for HTTP calls
- `openssl s_client` for TLS inspection
- `tcpdump` for packet capture

**Tranzia** consolidates these common workflows into a **unified, user-friendly CLI** — saving time and reducing mental load.

---

## ⚡ Current Features

- ✅ **TCP Echo Server** — Quickly start local echo servers for connectivity testing.
- ✅ **TCP Client** — Send raw messages to any TCP service.
- ✅ **Simple CLI Flags** — Minimalistic, intuitive options for faster usage.
- ✅ **Docker Support** — Run without installing Go or compiling.

---

## 🛠 Roadmap

🚧 Upcoming planned features:
- [ ] TLS & mTLS handshake testing
- [ ] Certificate inspection and validation
- [ ] SNI testing support
- [ ] HTTP/HTTPS debugging flows
- [ ] Protocol simulation (including TLV formats)
- [ ] Real-time packet capture with eBPF
- [ ] Latency, throughput, and load testing
- [ ] Plugin framework for extending with custom protocols

---

## 📦 Installation

### ✅ Build from source

```bash
git clone https://github.com/TranziaNet/tranzia.git
cd tranzia
make build
```

### ✅ Docker

```bash
docker pull ghcr.io/tranzianet/tranzia:latest
docker run --rm ghcr.io/tranzianet/tranzia:latest --help
```

### ✅ APT (Debian/Ubuntu)

#### Stable Channel (Currently in progress)

```bash
echo "deb [signed-by=/usr/share/keyrings/tranzia-archive-keyring.gpg] https://tranzianet.github.io/tranzia-apt-repo stable main" | sudo tee /etc/apt/sources.list.d/tranzia.list
sudo apt update && sudo apt install tranzia
```

#### Testing channel(Alpha/Beta builds)
```bash
echo "deb [signed-by=/usr/share/keyrings/tranzia-archive-keyring.gpg] https://tranzianet.github.io/tranzia-apt-repo testing main" | sudo tee /etc/apt/sources.list.d/tranzia-testing.list
sudo apt update && sudo apt install tranzia
```