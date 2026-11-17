package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ModelDirs 为常见模型目录（`~` 会展开）。
var ModelDirs = []string{
	"~/.ollama/models",
	"~/.cache/huggingface",
	"~/.cache/lm-studio",
	"/models",
	"/workspace",
}

// modelExts 为模型文件扩展名（含点）。
var modelExts = map[string]bool{
	".gguf": true, ".safetensors": true, ".onnx": true,
	".h5": true, ".pt": true, ".pth": true, ".sft": true,
}

// ScanModelFile 读取模型文件指纹（格式 + 元数据 + 采样哈希）。
func ScanModelFile(path string) (*ModelFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s 是目录", path)
	}

	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	mf := &ModelFile{
		Path:   path,
		Size:   st.Size(),
		Format: detectFormat(head, filepath.Ext(path)),
	}

	switch mf.Format {
	case "gguf":
		parseGGUFHeader(f, mf)
	case "safetensors":
		parseSafetensorsHeader(f, mf)
	}

	if h, err := sampleHash(path, st.Size()); err == nil {
		mf.Hash = h
	}
	return mf, nil
}

// detectFormat 根据魔数判断模型格式（magic 不足时回退扩展名）。
func detectFormat(head []byte, ext string) string {
	if len(head) >= 4 {
		switch string(head[:4]) {
		case "GGUF":
			return "gguf"
		case "\x89HDF":
			return "hdf5"
		case "PK\x03\x04":
			if ext == ".pt" || ext == ".pth" {
				return "pytorch"
			}
			return "zip"
		}
	}
	if len(head) >= 1 && head[0] == 0x80 {
		return "pickle"
	}
	// safetensors：前 8 字节为 JSON 头长度（小端），第 9 字节起为 JSON
	if len(head) >= 9 {
		n := binary.LittleEndian.Uint64(head[:8])
		if n > 0 && n < 100*1024*1024 && head[8] == '{' {
			return "safetensors"
		}
	}
	if ext == ".onnx" {
		return "onnx"
	}
	return "unknown"
}

// parseGGUFHeader 解析 GGUF 元数据（architecture / file_type）。
// 遇到数组等变长类型即停止（保护性上限 64 个 KV）。
func parseGGUFHeader(f *os.File, mf *ModelFile) {
	var hdr [24]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return
	}
	kvCount := binary.LittleEndian.Uint64(hdr[16:24])

	off := int64(24)
	for i := uint64(0); i < kvCount && i < 64; i++ {
		key, next, ok := readGGUFKey(f, off)
		if !ok {
			return
		}
		off = next

		var vtypeBuf [4]byte
		if _, err := f.ReadAt(vtypeBuf[:], off); err != nil {
			return
		}
		vtype := binary.LittleEndian.Uint32(vtypeBuf[:])
		off += 4

		switch vtype {
		case 8: // string
			s, next, ok := readGGUFString(f, off)
			if !ok {
				return
			}
			if key == "general.architecture" {
				mf.Arch = s
			}
			off = next
		case 4: // uint32
			var vbuf [4]byte
			if _, err := f.ReadAt(vbuf[:], off); err != nil {
				return
			}
			if key == "general.file_type" {
				mf.Quant = ggufQuantName(binary.LittleEndian.Uint32(vbuf[:]))
			}
			off += 4
		case 0, 1, 7: // uint8/int8/bool
			off++
		case 2, 3: // uint16/int16
			off += 2
		case 6: // float32
			off += 4
		case 10, 11, 12: // uint64/int64/float64
			off += 8
		default:
			// 数组等变长类型：停止解析
			return
		}
	}
}

// readGGUFKey 读取 GGUF metadata key（u64 长度 + UTF-8）。
func readGGUFKey(f *os.File, off int64) (string, int64, bool) {
	var lenBuf [8]byte
	if _, err := f.ReadAt(lenBuf[:], off); err != nil {
		return "", 0, false
	}
	n := binary.LittleEndian.Uint64(lenBuf[:])
	if n == 0 || n > 4096 {
		return "", 0, false
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, off+8); err != nil {
		return "", 0, false
	}
	return string(buf), off + 8 + int64(n), true
}

// readGGUFString 读取 GGUF string 值（u64 长度 + UTF-8）。
func readGGUFString(f *os.File, off int64) (string, int64, bool) {
	var lenBuf [8]byte
	if _, err := f.ReadAt(lenBuf[:], off); err != nil {
		return "", 0, false
	}
	n := binary.LittleEndian.Uint64(lenBuf[:])
	if n > 65536 {
		return "", 0, false
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, off+8); err != nil {
		return "", 0, false
	}
	return string(buf), off + 8 + int64(n), true
}

// ggufQuantName 将 GGUF general.file_type 映射为量化名称。
func ggufQuantName(t uint32) string {
	switch t {
	case 0:
		return "F32"
	case 1:
		return "F16"
	case 2:
		return "Q4_0"
	case 3:
		return "Q4_1"
	case 7:
		return "Q8_0"
	case 8:
		return "Q5_0"
	case 9:
		return "Q5_1"
	case 10:
		return "Q2_K"
	case 11:
		return "Q3_K_S"
	case 12:
		return "Q3_K_M"
	case 13:
		return "Q3_K_L"
	case 14:
		return "Q4_K_S"
	case 15:
		return "Q4_K_M"
	case 16:
		return "Q5_K_S"
	case 17:
		return "Q5_K_M"
	case 18:
		return "Q6_K"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

// parseSafetensorsHeader 解析 safetensors 的 JSON 头（__metadata__）。
func parseSafetensorsHeader(f *os.File, mf *ModelFile) {
	var lenBuf [8]byte
	if _, err := f.ReadAt(lenBuf[:], 0); err != nil {
		return
	}
	n := binary.LittleEndian.Uint64(lenBuf[:])
	if n == 0 || n > 100*1024*1024 {
		return
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 8); err != nil {
		return
	}

	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(buf, &hdr); err != nil {
		return
	}
	metaRaw, ok := hdr["__metadata__"]
	if !ok {
		return
	}
	var meta map[string]string
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return
	}
	if v, ok := meta["format"]; ok && v != "" {
		mf.Format = "safetensors:" + v
	}
	if v, ok := meta["architecture"]; ok {
		mf.Arch = v
	}
}

// sampleHash 计算采样哈希（头 1MB + 尾 1MB + size，避免全量读取大模型）。
func sampleHash(path string, size int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	const chunk = 1 << 20

	head := make([]byte, chunk)
	n, _ := io.ReadFull(f, head)
	h.Write(head[:n])

	if size > 2*chunk {
		if _, err := f.Seek(size-chunk, io.SeekStart); err == nil {
			tail := make([]byte, chunk)
			n, _ := io.ReadFull(f, tail)
			h.Write(tail[:n])
		}
	}

	var sz [8]byte
	binary.LittleEndian.PutUint64(sz[:], uint64(size))
	h.Write(sz[:])

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ScanModelDirs 扫描常见目录下的模型文件（按扩展名）。
func ScanModelDirs(dirs []string) ([]ModelFile, error) {
	var out []ModelFile
	for _, dir := range dirs {
		dir = expandHome(dir)
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !modelExts[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			if mf, err := ScanModelFile(p); err == nil {
				out = append(out, *mf)
			}
			return nil
		})
	}
	return out, nil
}

// expandHome 展开路径开头的 `~`。
func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
