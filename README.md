# 🌐 Tranzia

🚀 **Tranzia** aims to be your **all-in-one CLI toolkit for network testing and debugging**, unifying tools like `nc`, `curl`, `openssl`, and `tcpdump` under a **single, modern, extensible umbrella**.

> **⚠️ Note:** Tranzia is in **early development**, and many of the planned features below are part of our **future roadmap**.

---

## ✨ Why Tranzia?

Today, developers and SREs rely on a fragmented set of tools:
- `nc` for raw TCP tests
- `curl` for HTTP checks
- `openssl s_client` for TLS verification
- `tcpdump` for packet capture

**Tranzia’s vision** is to bring these capabilities under a **cohesive, clean CLI experience**, simplifying your workflow and making network debugging and testing more efficient.

---

## ⚡ Current Features

✅ Lightweight TCP echo server for local testing  
✅ TCP client for sending messages and receiving responses  
✅ Easy CLI flags for configuration

---

## 🛠 Planned Features (Roadmap)

🚧 These features are planned for future development:

- [ ] TLS and mTLS handshake and certificate validation
- [ ] SNI-based connection testing
- [ ] Latency and throughput measurement
- [ ] Packet capture and analysis (pcap/eBPF integration planned)
- [ ] TLV-based protocol simulation
- [ ] HTTP(S) debugging workflows
- [ ] Modular plugin support for protocol testing
- [ ] Load and concurrency testing

---

## 📦 Installation

### Build from source

```bash
git clone https://github.com/TranziaNet/tranzia.git
cd tranzia
make build
```