package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TranziaNet/tranzia/pkg/cmd"
	"github.com/spf13/cobra/doc"
)

func main() {
	outDir := "./docs"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatal(err)
	}

	// Step 1: Generate CLI docs
	err := doc.GenMarkdownTree(cmd.RootCmd, outDir)
	if err != nil {
		log.Fatalf("Failed to generate CLI docs: %v", err)
	}

	// Step 2: Generate index.md
	generateIndex(outDir)

	// Step 3: Sanity check to ensure docs were generated
	if _, err := os.Stat(filepath.Join(outDir, "index.md")); err != nil {
		log.Fatal("Docs not generated properly: index.md missing")
	}

	files, err := os.ReadDir(outDir)
	if err != nil {
		log.Fatal("Failed to read docs directory:", err)
	}
	if len(files) <= 1 {
		log.Fatalf("Docs generation incomplete: only %d file(s) generated", len(files))
	}

	log.Printf("Docs generated successfully with %d files", len(files))
}

func generateIndex(docsDir string) {
	files, err := os.ReadDir(docsDir)
	if err != nil {
		log.Fatal(err)
	}

	var links []string
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || name == "index.md" || !strings.HasSuffix(name, ".md") {
			continue
		}
		title := strings.TrimSuffix(name, ".md")
		links = append(links, fmt.Sprintf("- [%s](%s)", title, name))
	}

	sort.Strings(links)

	indexTemplate := `# Tranzia CLI Documentation

Welcome to the **Tranzia** CLI documentation!  
Tranzia is a modern, unified CLI toolkit for developers, DevOps, and SREs, combining networking tools like ` + "`curl`" + `, ` + "`nc`" + `, ` + "`openssl`" + `, and ` + "`tcpdump`" + ` under one interface.

---

## 📚 Available Commands

` + strings.Join(links, "\n") + `

---

## 📝 How to Use Tranzia

- To view available commands:

` + "```bash\ntranzia --help\n```" + `

- To get help for any command:

` + "```bash\ntranzia <command> --help\n```" + `

Examples:

- Basic TCP client:

` + "```bash\ntranzia tcp client --host example.com --port 9000\n```" + `

- Generate TLS certificate:

` + "```bash\ntranzia tls cert generate --key-type rsa --subject \"/CN=example.com/O=Org\"\n```" + `

---

## 💡 Resources
- [GitHub Repository](https://github.com/TranziaNet/tranzia)
- [Releases](https://github.com/TranziaNet/tranzia/releases)
- [Report Issues](https://github.com/TranziaNet/tranzia/issues)

---

_Auto-generated using Cobra CLI tools._
`

	finalContent := strings.Replace(indexTemplate, "{{generated_links}}", strings.Join(links, "\n"), 1)

	err = os.WriteFile(filepath.Join(docsDir, "index.md"), []byte(finalContent), 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("✅ index.md generated with %d entries", len(links))
}
