package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

//go:embed reverse_hermes.py
var reverseHermesScript string

const maxDerivedMaterial = 64 << 20

type reverseDerived struct {
	ArtifactID      int64  `json:"artifact_id"`
	ParentSHA256    string `json:"parent_sha256"`
	Entry           string `json:"entry"`
	Path            string `json:"derived_path"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size_bytes"`
	Format          string `json:"format"`
	BytecodeVersion uint32 `json:"bytecode_version,omitempty"`
}

func reverseMaterialFormat(head []byte, name string) (string, uint32) {
	if len(head) >= 12 && binary.LittleEndian.Uint64(head[:8]) == 0x1F1903C103BC1FC6 {
		return "hermes", binary.LittleEndian.Uint32(head[8:12])
	}
	ext := strings.ToLower(path.Ext(name))
	if utf8.Valid(head) {
		switch ext {
		case ".js", ".mjs", ".cjs", ".bundle":
			return "javascript", 0
		case ".html", ".htm":
			return "html", 0
		}
	}
	if len(head) >= 4 && string(head[:4]) == "\x7fELF" {
		return "native", 0
	}
	if len(head) >= 4 && string(head[:4]) == "dex\n" {
		return "dex", 0
	}
	return "binary", 0
}

func prepareReverseAPK(ctx context.Context, artifact *db.ReverseArtifact, workDir, entry string, offset, limit int) (map[string]any, error) {
	if err := verifyArtifact(artifact); err != nil {
		return nil, err
	}
	if err := checkAPKDirectoryBound(artifact.Path); err != nil {
		return nil, err
	}
	z, err := zip.OpenReader(artifact.Path)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	if len(z.File) > 20000 {
		return nil, errors.New("APK 条目超过20000，请使用更小材料")
	}
	if entry == "" {
		rows := []map[string]any{}
		for _, f := range z.File {
			if f.FileInfo().IsDir() {
				continue
			}
			name := strings.ToLower(f.Name)
			if strings.HasSuffix(name, ".dex") || strings.HasSuffix(name, ".so") || strings.HasPrefix(name, "assets/") {
				rows = append(rows, map[string]any{"entry": f.Name, "size_bytes": f.UncompressedSize64, "compressed_bytes": f.CompressedSize64})
			}
		}
		offset = min(max(0, offset), len(rows))
		limit = min(max(1, limit), 100)
		end := min(len(rows), offset+limit)
		return map[string]any{"artifact_id": artifact.ID, "sha256": artifact.SHA256, "total": len(rows), "items": rows[offset:end], "next_offset": end, "next": "选定entry再次调用以提取并识别真实格式；普通JS与Hermes字节码使用不同分析路线"}, nil
	}
	if path.IsAbs(entry) || strings.Contains(entry, "\\") || path.Clean(entry) != entry || entry == ".." || strings.HasPrefix(entry, "../") {
		return nil, errors.New("无效 APK 条目路径")
	}
	var selected *zip.File
	for _, f := range z.File {
		if f.Name == entry {
			if selected != nil {
				return nil, errors.New("APK 包含同名重复条目")
			}
			selected = f
		}
	}
	if selected == nil || selected.FileInfo().IsDir() || selected.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("未找到普通 APK 条目")
	}
	if selected.UncompressedSize64 > maxDerivedMaterial {
		return nil, errors.New("APK 子材料超过64MiB")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := selected.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxDerivedMaterial+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDerivedMaterial {
		return nil, errors.New("APK 子材料超过64MiB")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	sha := hex.EncodeToString(digest[:])
	format, v := reverseMaterialFormat(data, entry)
	// A fresh private directory avoids following caller-controlled paths/symlinks.
	base := filepath.Join(workDir, "tasks", strconv.FormatInt(artifact.TaskID, 10), "reverse", "derived")
	if err = os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	relBase := filepath.Join("tasks", strconv.FormatInt(artifact.TaskID, 10), "reverse", "derived")
	if _, err = reverseLocalPath(workDir, relBase, relBase); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "material-")
	if err != nil {
		return nil, err
	}
	target := filepath.Join(dir, "sample"+path.Ext(entry))
	if err = os.WriteFile(target, data, 0600); err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(workDir, target)
	derived := reverseDerived{ArtifactID: artifact.ID, ParentSHA256: artifact.SHA256, Entry: entry, Path: filepath.ToSlash(rel), SHA256: sha, Size: int64(len(data)), Format: format, BytecodeVersion: v}
	return map[string]any{"derived": derived, "analysis_route": map[string]string{"hermes": "reverse_inspect_hermes", "javascript": "rea_call analyze_javascript_application (input_path为子材料所在目录)", "native": "REA native static tools", "dex": "REA Android tools using parent APK"}[format]}, nil
}

// Inspect the bounded EOCD before archive/zip allocates the central directory.
// Multi-disk and ZIP64 archives require a separate route and are not APK inputs
// supported by this adapter.
func checkAPKDirectoryBound(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	n := min(st.Size(), int64(65535+22))
	if n < 22 {
		return errors.New("无效APK归档")
	}
	tail := make([]byte, n)
	if _, err = f.ReadAt(tail, st.Size()-n); err != nil {
		return err
	}
	for end := len(tail) - 22; end >= 0; end-- {
		if string(tail[end:end+4]) != "PK\x05\x06" {
			continue
		}
		b := tail[end:]
		if len(b) != 22+int(binary.LittleEndian.Uint16(b[20:22])) {
			continue
		}
		count := binary.LittleEndian.Uint16(b[10:12])
		size := binary.LittleEndian.Uint32(b[12:16])
		if binary.LittleEndian.Uint16(b[4:6]) != 0 || binary.LittleEndian.Uint16(b[6:8]) != 0 || count == 65535 || size == 0xffffffff {
			return errors.New("不支持多磁盘或ZIP64 APK")
		}
		if count > 20000 || size > 16<<20 {
			return errors.New("APK中央目录超过限制")
		}
		return nil
	}
	return errors.New("APK缺少有效中央目录")
}

func saveReverseMaterialResult(workDir string, taskID int64, operation string, artifact *db.ReverseArtifact, result any) (actool.Result, error) {
	dir := filepath.Join(workDir, "tasks", strconv.FormatInt(taskID, 10), "reverse", "results")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return actool.Result{}, err
	}
	prefix := filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "results")
	if _, err := reverseLocalPath(workDir, prefix, prefix); err != nil {
		return actool.Result{}, err
	}
	raw, err := json.Marshal(map[string]any{"isError": false, "structuredContent": map[string]any{"operation": operation, "subject": map[string]any{"digest": map[string]any{"sha256": artifact.SHA256}}, "confidence": "observed", "authority": "shipped-artifact", "normalized_result": result}})
	if err != nil {
		return actool.Result{}, err
	}
	f, err := os.CreateTemp(dir, "material-*.json")
	if err != nil {
		return actool.Result{}, err
	}
	defer f.Close()
	f.Chmod(0600)
	if _, err = f.Write(raw); err != nil {
		return actool.Result{}, err
	}
	if err = f.Sync(); err != nil {
		return actool.Result{}, err
	}
	rel, _ := filepath.Rel(workDir, f.Name())
	return reverseJSON(map[string]any{"result_path": filepath.ToSlash(rel), "result": result, "note": "派生材料保留父APK/条目/子文件哈希；只做静态分析"}), nil
}

func loadReverseDerived(pg *db.DB, taskID int64, workDir, receipt string) (*db.ReverseArtifact, *reverseDerived, error) {
	p, err := reverseLocalPath(workDir, receipt, filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "results"))
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var doc struct {
		Structured struct {
			Result struct {
				Derived reverseDerived `json:"derived"`
			} `json:"normalized_result"`
		} `json:"structuredContent"`
	}
	if err = json.NewDecoder(io.LimitReader(f, 2<<20)).Decode(&doc); err != nil {
		return nil, nil, err
	}
	d := doc.Structured.Result.Derived
	a, err := pg.GetReverseArtifact(taskID, d.ArtifactID)
	if err != nil || a == nil {
		return nil, nil, errors.New("派生材料的父工件不存在")
	}
	a.Path, err = reverseLocalPath(workDir, a.Path, filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "artifacts"))
	if err != nil {
		return nil, nil, err
	}
	if err = verifyArtifact(a); err != nil {
		return nil, nil, err
	}
	if a.SHA256 != d.ParentSHA256 {
		return nil, nil, errors.New("父工件版本不一致")
	}
	d.Path, err = reverseLocalPath(workDir, d.Path, filepath.Join("tasks", strconv.FormatInt(taskID, 10), "reverse", "derived"))
	if err != nil {
		return nil, nil, err
	}
	f2, err := os.Open(d.Path)
	if err != nil {
		return nil, nil, err
	}
	defer f2.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f2, maxDerivedMaterial+1))
	if err != nil || n != d.Size || hex.EncodeToString(h.Sum(nil)) != d.SHA256 {
		return nil, nil, errors.New("派生材料哈希或大小变化")
	}
	return a, &d, nil
}

func inspectReverseHermes(ctx context.Context, request map[string]any) (json.RawMessage, error) {
	python := strings.TrimSpace(os.Getenv("ARTEX_HERMES_PYTHON"))
	if python == "" {
		python = filepath.Join(config.BaseDir(), "tools", "hermes", "bin", "python")
	}
	if _, err := exec.LookPath(python); err != nil {
		return nil, errors.New("Hermes引擎未就绪；运行scripts/install-hermes.sh安装固定版本并设置ARTEX_HERMES_PYTHON")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, _ := json.Marshal(request)
	cmd := exec.CommandContext(ctx, python, "-c", reverseHermesScript)
	cmd.Stdin = bytes.NewReader(raw)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	out, readErr := io.ReadAll(io.LimitReader(pipe, 1<<20+1))
	if len(out) > 1<<20 || readErr != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, errors.New("Hermes结果超过限制或读取失败")
	}
	if err = cmd.Wait(); err != nil {
		return nil, errors.New("Hermes分析超时或解析失败；未执行材料")
	}
	var answer struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(out, &answer) != nil {
		return nil, errors.New("Hermes返回无效结果")
	}
	if !answer.OK {
		return nil, fmt.Errorf("Hermes静态分析受阻: %s", answer.Error)
	}
	return answer.Result, nil
}

func reverseMaterialTools(pg *db.DB, task *db.Task, info agent.RunInfo, workDir string) []actool.CoreTool {
	_ = info
	return []actool.CoreTool{
		reverseTool("reverse_prepare_apk", "核对父APK哈希，列出DEX/assets/native子材料；entry指定精确ZIP条目时受限提取并识别JS/Hermes/DEX/ELF，保留父子哈希；不执行程序。", reverseObject(map[string]any{"artifact_id": reverseInt(), "entry": reverseString(), "offset": reverseInt(), "limit": reverseInt()}, "artifact_id"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				ID            int64 `json:"artifact_id"`
				Entry         string
				Offset, Limit int
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			a, err := pg.GetReverseArtifact(task.ID, in.ID)
			if err != nil || a == nil {
				return actool.Errorf("APK材料不存在"), nil
			}
			a.Path, err = reverseLocalPath(workDir, a.Path, filepath.Join("tasks", strconv.FormatInt(task.ID, 10), "reverse", "artifacts"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Format != "apk" {
				return actool.Errorf("仅支持已登记APK材料"), nil
			}
			if in.Limit == 0 {
				in.Limit = 50
			}
			result, err := prepareReverseAPK(ctx, a, workDir, in.Entry, in.Offset, in.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			answer, err := saveReverseMaterialResult(workDir, task.ID, "reverse_prepare_apk", a, result)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return answer, nil
		}),
		reverseTool("reverse_inspect_hermes", "读取reverse_prepare_apk的result_path，静态查询Hermes字节码摘要/字符串/函数索引/指定函数指令，支持query与分页。不执行字节码，不把反汇编当原始JS。", reverseObject(map[string]any{"result_path": reverseString(), "facet": map[string]any{"type": "string", "enum": []string{"summary", "strings", "functions", "instructions"}}, "query": reverseString(), "function_id": reverseInt(), "offset": reverseInt(), "limit": reverseInt()}, "result_path", "facet"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in map[string]any
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ref, _ := in["result_path"].(string)
			a, d, err := loadReverseDerived(pg, task.ID, workDir, ref)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if d.Format != "hermes" {
				return actool.Errorf("派生材料不是Hermes字节码"), nil
			}
			in["path"] = d.Path
			result, err := inspectReverseHermes(ctx, in)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			rel, _ := filepath.Rel(workDir, d.Path)
			d.Path = filepath.ToSlash(rel)
			answer, err := saveReverseMaterialResult(workDir, task.ID, "reverse_inspect_hermes", a, map[string]any{"derived": d, "analysis": result})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return answer, nil
		}),
		reverseTool("reverse_read_derived", "按字符分页读取已验证派生JS/HTML文本；Hermes必须使用reverse_inspect_hermes。result_path来自reverse_prepare_apk。", reverseObject(map[string]any{"result_path": reverseString(), "offset": reverseInt(), "limit": reverseInt()}, "result_path"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				Ref           string `json:"result_path"`
				Offset, Limit int
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			_, d, err := loadReverseDerived(pg, task.ID, workDir, in.Ref)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if d.Format != "javascript" && d.Format != "html" {
				return actool.Errorf("只支持JS/HTML文本；Hermes需专用静态分析"), nil
			}
			data, err := os.ReadFile(d.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !utf8.Valid(data) {
				return actool.Errorf("不是有效UTF8文本"), nil
			}
			runes := []rune(string(data))
			in.Offset = min(max(0, in.Offset), len(runes))
			if in.Limit < 1 || in.Limit > 4000 {
				in.Limit = 4000
			}
			end := min(len(runes), in.Offset+in.Limit)
			return reverseJSON(map[string]any{"sha256": d.SHA256, "entry": d.Entry, "source": string(runes[in.Offset:end]), "offset": in.Offset, "next_offset": end, "total": len(runes)}), nil
		}),
	}
}
