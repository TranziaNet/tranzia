# Tranzia CLI Documentation

Welcome to the **Tranzia** CLI documentation!  
Tranzia is a modern, unified CLI toolkit for developers, DevOps, and SREs, combining networking tools like `curl`, `nc`, `openssl`, and `tcpdump` under one interface.

---

## 📚 Available Commands

- [tranzia](tranzia.md)
- [tranzia_echo-server](tranzia_echo-server.md)
- [tranzia_send](tranzia_send.md)
- [tranzia_tls](tranzia_tls.md)
- [tranzia_tls_cert](tranzia_tls_cert.md)
- [tranzia_tls_cert_generate](tranzia_tls_cert_generate.md)
- [tranzia_tls_cert_inspect](tranzia_tls_cert_inspect.md)

---

## 📝 How to Use Tranzia

- To view available commands:

```bash
tranzia --help
```

- To get help for any command:

```bash
tranzia <command> --help
```

Examples:

- Basic TCP client:

```bash
tranzia tcp client --host example.com --port 9000
```

- Generate TLS certificate:

```bash
tranzia tls cert generate --key-type rsa --subject "/CN=example.com/O=Org"
```

---

## 💡 Resources
- [GitHub Repository](https://github.com/TranziaNet/tranzia)
- [Releases](https://github.com/TranziaNet/tranzia/releases)
- [Report Issues](https://github.com/TranziaNet/tranzia/issues)

---

_Auto-generated using Cobra CLI tools._
