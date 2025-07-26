package cert_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TranziaNet/tranzia/pkg/tls/cert"
)

const samplePEM = `-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIRAIyrSotm1PysfeaVShagMGwwCgYIKoZIzj0EAwIwKjES
MBAGA1UEBxMJc3Vubnl2YWxlMRQwEgYDVQQDEwtleGFtcGxlLmNvbTAeFw0yNTA3
MjYwNTM5NTBaFw0yNjA3MjYwNTM5NTBaMCoxEjAQBgNVBAcTCXN1bm55dmFsZTEU
MBIGA1UEAxMLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA
BVe5ngsIknmbjRzsVWiL4OftFxEo+v4oi4X2PiFxi+vxwba9q00obd/Vgnszt9nn
G/vOlXXcGibVsIUyiy42o0IwQDAOBgNVHQ8BAf8EBAMCB4AwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQU1cPv1Nf/T9uX3aZF8ZBwkt/457UwCgYIKoZIzj0EAwID
SAAwRQIhAIIq9vsjtRxNqNKDdz7a64O6avxu/joJKRO0pUBkE8sdAiA/PEqROKIZ
Prnf9wl4dNnlRSv0xIki6vO9QVRKzIqIzg==
-----END CERTIFICATE-----
`

func writeTempCert(t *testing.T, content string) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cert.pem")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	return path
}

func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, r)
		close(done)
	}()

	f()
	w.Close()
	os.Stdout = old
	<-done
	return buf.String()
}

func TestCertInspect_PEMText(t *testing.T) {
	cert.InspectOpts = cert.InspectOptions{Format: "pem", OutputJSON: false}
	path := writeTempCert(t, samplePEM)

	output := captureOutput(func() {
		err := cert.CertInspect.RunE(cert.CertInspect, []string{path})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(output, "Subject:") || !strings.Contains(output, "Issuer:") {
		t.Errorf("expected formatted cert info, got: %s", output)
	}
}

func TestCertInspect_PEMJSON(t *testing.T) {
	cert.InspectOpts = cert.InspectOptions{Format: "pem", OutputJSON: true}
	path := writeTempCert(t, samplePEM)

	output := captureOutput(func() {
		err := cert.CertInspect.RunE(cert.CertInspect, []string{path, "--json"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(output, `"commonName"`) {
		t.Errorf("expected JSON output, got: %s", output)
	}
}

func TestCertInspect_InvalidPath(t *testing.T) {
	cert.InspectOpts = cert.InspectOptions{}
	err := cert.CertInspect.RunE(cert.CertInspect, []string{"nonexistent.pem"})
	if err == nil {
		t.Error("expected error for missing file, got none")
	}
}

func TestCertInspect_InvalidPEM(t *testing.T) {
	invalid := "-----BEGIN GARBAGE-----\nMIIBfakecertdata\n-----END GARBAGE-----"
	path := writeTempCert(t, invalid)
	cert.InspectOpts = cert.InspectOptions{Format: "pem", OutputJSON: false}

	err := cert.CertInspect.RunE(cert.CertInspect, []string{path})
	if err == nil {
		t.Error("expected parse error, got none")
	}
}
