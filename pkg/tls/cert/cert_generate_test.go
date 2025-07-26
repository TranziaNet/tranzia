package cert_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/TranziaNet/tranzia/pkg/tls/cert"
)

func TestGenerateKeyPair_RSA(t *testing.T) {
	opts := &cert.CertGenerateOptions{KeyType: "rsa", Bits: 2048}
	key, err := cert.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("expected RSA private key, got %T", key)
	}
}

func TestGenerateKeyPair_ECDSA(t *testing.T) {
	opts := &cert.CertGenerateOptions{KeyType: "ecdsa", Bits: 384}
	key, err := cert.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected ECDSA private key, got %T", key)
	}
}

func TestGenerateKeyPair_Ed25519(t *testing.T) {
	opts := &cert.CertGenerateOptions{KeyType: "ed25519"}
	key, err := cert.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if _, ok := key.(ed25519.PrivateKey); !ok {
		t.Errorf("expected Ed25519 private key, got %T", key)
	}
}

func TestGenerateKeyPair_Invalid(t *testing.T) {
	opts := &cert.CertGenerateOptions{KeyType: "dsa"}
	_, err := cert.GenerateKeyPair(opts)
	if err == nil {
		t.Error("expected error for unsupported key type, got none")
	}
}

func TestGenerateCertificateTemplate_Basic(t *testing.T) {
	opts := &cert.CertGenerateOptions{
		Subject:  &cert.Sub{CN: "example.com", O: []string{"Tranzia"}},
		Validity: 365,
		Usage:    "DigitalSignature,KeyEncipherment",
		IsCA:     true,
	}
	tmpl, err := cert.GenerateCertificateTemplate(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Subject.CommonName != "example.com" {
		t.Errorf("expected CN to be example.com, got %s", tmpl.Subject.CommonName)
	}
	if !tmpl.IsCA {
		t.Error("expected IsCA to be true")
	}
}

func TestGenerateOutput_WritesFiles(t *testing.T) {
	tmp := t.TempDir()
	opts := &cert.CertGenerateOptions{
		KeyType:            "rsa",
		OutCertFilePath:    filepath.Join(tmp, "cert.pem"),
		OutPrivKeyFilePath: filepath.Join(tmp, "key.pem"),
		OutPubKeyFilePath:  filepath.Join(tmp, "pub.pem"),
		Validity:           365,
		Subject:            &cert.Sub{CN: "test.local"},
		Bits:               2048,
	}

	// Silence stdout/stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	devNull, _ := os.Open(os.DevNull)
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		devNull.Close()
	}()
	os.Stdout = devNull
	os.Stderr = devNull

	privKey, err := cert.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("unexpected key gen error: %v", err)
	}

	tmpl, err := cert.GenerateCertificateTemplate(opts)
	if err != nil {
		t.Fatalf("unexpected template error: %v", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.(*rsa.PrivateKey).Public(), privKey)
	if err != nil {
		t.Fatalf("unexpected cert creation error: %v", err)
	}

	err = cert.GenerateOutput(privKey, certBytes, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range []string{
		opts.OutCertFilePath,
		opts.OutPrivKeyFilePath,
		opts.OutPubKeyFilePath,
	} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected file %s to exist, but got error: %v", f, err)
		}
	}
}
