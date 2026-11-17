package fingerprint

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestDetectFormat 验证魔数/扩展名格式识别。
func TestDetectFormat(t *testing.T) {
	safetensorsJSON := `{"__metadata__":{}}`
	safetensorsHead := make([]byte, 9)
	binary.LittleEndian.PutUint64(safetensorsHead[:8], uint64(len(safetensorsJSON)))
	safetensorsHead[8] = '{'

	cases := []struct {
		name string
		head []byte
		ext  string
		want string
	}{
		{"gguf", []byte("GGUF\x03\x00\x00\x00"), ".gguf", "gguf"},
		{"hdf5", []byte("\x89HDF\r\n\x1a\n"), ".h5", "hdf5"},
		{"pickle", []byte{0x80, 0x04}, ".pkl", "pickle"},
		{"zip-pt", []byte("PK\x03\x04"), ".pt", "pytorch"},
		{"zip", []byte("PK\x03\x04"), ".bin", "zip"},
		{"onnx", []byte{0x08, 0x01}, ".onnx", "onnx"},
		{"safetensors", safetensorsHead, ".safetensors", "safetensors"},
		{"unknown", []byte{0x00}, ".bin", "unknown"},
	}
	for _, c := range cases {
		if got := detectFormat(c.head, c.ext); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestScanModelFileGGUF 验证 GGUF 文件扫描（格式 + 大小 + 哈希）。
func TestScanModelFileGGUF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.gguf")
	// GGUF header: magic(4) + version(4) + tensor_count(8) + kv_count(8)
	buf := make([]byte, 24)
	copy(buf[0:4], "GGUF")
	binary.LittleEndian.PutUint32(buf[4:8], 3)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	mf, err := ScanModelFile(path)
	if err != nil {
		t.Fatalf("ScanModelFile 失败: %v", err)
	}
	if mf.Format != "gguf" {
		t.Fatalf("Format = %q，期望 gguf", mf.Format)
	}
	if mf.Size != 24 {
		t.Fatalf("Size = %d，期望 24", mf.Size)
	}
	if mf.Hash == "" {
		t.Fatal("Hash 为空")
	}
}

// TestScanModelFileSafetensors 验证 safetensors 头解析（__metadata__）。
func TestScanModelFileSafetensors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.safetensors")
	jsonHdr := `{"__metadata__":{"format":"pt","architecture":"llama"}}`
	buf := make([]byte, 8+len(jsonHdr))
	binary.LittleEndian.PutUint64(buf[:8], uint64(len(jsonHdr)))
	copy(buf[8:], jsonHdr)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	mf, err := ScanModelFile(path)
	if err != nil {
		t.Fatalf("ScanModelFile 失败: %v", err)
	}
	if mf.Format != "safetensors:pt" {
		t.Fatalf("Format = %q，期望 safetensors:pt", mf.Format)
	}
	if mf.Arch != "llama" {
		t.Fatalf("Arch = %q，期望 llama", mf.Arch)
	}
}

// TestSampleHash 验证采样哈希对大小/内容敏感。
func TestSampleHash(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.gguf")
	p2 := filepath.Join(dir, "b.gguf")
	if err := os.WriteFile(p1, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("hello!"), 0o600); err != nil {
		t.Fatal(err)
	}

	h1, err := sampleHash(p1, 5)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := sampleHash(p2, 6)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == "" || h2 == "" {
		t.Fatal("哈希为空")
	}
	if h1 == h2 {
		t.Fatal("不同内容/大小的哈希不应相同")
	}
}
