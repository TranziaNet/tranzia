package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TranziaNet/tranzia/pkg/cmd"
	_ "github.com/TranziaNet/tranzia/pkg/tls"
	_ "github.com/TranziaNet/tranzia/pkg/tls/cert"

	"github.com/spf13/cobra/doc"
)

func main() {
	outDir := "./docs"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("❌ Failed to create output directory: %v", err)
	}

	log.Printf("📘 Generating CLI docs to %s", outDir)
	if err := doc.GenMarkdownTree(cmd.RootCmd, outDir); err != nil {
		log.Fatalf("❌ Failed to generate CLI docs: %v", err)
	}

	files, err := os.ReadDir(outDir)
	if err != nil {
		log.Fatalf("❌ Failed to read docs directory: %v", err)
	}
	mdFiles := filterMarkdownFiles(files)
	if len(mdFiles) == 0 {
		log.Fatal("❌ No CLI Markdown files generated. Are subcommands registered?")
	}

	generateSimpleIndex(outDir, mdFiles)

	log.Printf("✅ CLI docs generated: %d files", len(mdFiles)+1) // +1 for index.md
}

func filterMarkdownFiles(files []os.DirEntry) []os.DirEntry {
	var md []os.DirEntry
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") && f.Name() != "index.md" {
			md = append(md, f)
		}
	}
	return md
}

func generateSimpleIndex(outDir string, files []os.DirEntry) {
	var lines []string
	for _, f := range files {
		name := f.Name()
		title := strings.TrimSuffix(name, ".md")
		lines = append(lines, fmt.Sprintf("- [%s](%s)", title, name))
	}
	sort.Strings(lines)

	index := "# CLI Command Reference\n\n" + strings.Join(lines, "\n") + "\n"

	if err := os.WriteFile(filepath.Join(outDir, "index.md"), []byte(index), 0644); err != nil {
		log.Fatalf("❌ Failed to write index.md: %v", err)
	}
	log.Printf("📄 index.md generated with %d entries", len(lines))
}
