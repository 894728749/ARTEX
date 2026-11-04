package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

const maxReverseArtifact = 256 << 20

func (s *Server) reverseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/tasks/{id}/reverse/artifacts", s.reverseArtifactUpload)
	mux.HandleFunc("GET /api/tasks/{id}/reverse/artifacts", s.reverseArtifactList)
	mux.HandleFunc("GET /api/tasks/{id}/reverse/artifacts/{aid}/download", s.reverseArtifactDownload)
	mux.HandleFunc("GET /api/tasks/{id}/reverse/conclusions", s.reverseConclusionList)
}

func (s *Server) reverseIDs(r *http.Request) (int64, int64, bool) {
	tid, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || tid <= 0 {
		return 0, 0, false
	}
	t, ok := s.m.Task(strconv.FormatInt(tid, 10))
	if !ok || t.Kind != "reverse" {
		return 0, 0, false
	}
	return tid, 0, true
}
func reverseName(n string) string {
	n = filepath.Base(strings.ReplaceAll(n, "\\", "/"))
	if n == "" || n == "." || n == ".." {
		return "artifact"
	}
	return n
}
func (s *Server) reverseArtifactUpload(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := s.reverseIDs(r)
	if !ok {
		writeErr(w, 404, "逆向任务不存在")
		return
	}
	task, _ := s.m.Task(strconv.FormatInt(tid, 10))
	life := task.lifecycleSnapshot()
	if !life.Paused && !db.IsTerminal(life.Status) {
		writeErr(w, 409, "任务运行中不能上传材料")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxReverseArtifact+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeErr(w, 400, "上传解析失败或文件超过256MiB")
		return
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "缺少 file 文件")
		return
	}
	defer f.Close()
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(h.Filename)), ".")
	var rnd [16]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		writeErr(w, 500, "生成材料标识失败")
		return
	}
	base := hex.EncodeToString(rnd[:])
	if ext != "" && len(ext) < 16 {
		base += "." + ext
	}
	dir := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(tid, 10), "reverse", "artifacts")
	if err = os.MkdirAll(dir, 0700); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	dest := filepath.Join(dir, base)
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	okFile := false
	defer func() {
		_ = out.Close()
		if !okFile {
			_ = os.Remove(dest)
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(f, maxReverseArtifact+1))
	if err != nil {
		writeErr(w, 500, "材料写入失败")
		return
	}
	if n > maxReverseArtifact {
		writeErr(w, 400, "文件超过256MiB")
		return
	}
	if err = out.Sync(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err = out.Close(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	relPath := filepath.Join("tasks", strconv.FormatInt(tid, 10), "reverse", "artifacts", base)
	a, err := s.m.pg.AddReverseArtifact(tid, db.ReverseArtifact{Name: reverseName(h.Filename), Format: ext, SizeBytes: n, SHA256: hex.EncodeToString(hash.Sum(nil)), Source: r.FormValue("source"), Version: r.FormValue("version"), Path: relPath})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	okFile = true
	writeJSON(w, 201, a)
}
func (s *Server) reverseArtifactList(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := s.reverseIDs(r)
	if !ok {
		writeErr(w, 404, "逆向任务不存在")
		return
	}
	a, e := s.m.pg.ListReverseArtifacts(tid)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) reverseArtifactDownload(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := s.reverseIDs(r)
	aid, e := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if !ok || e != nil || aid <= 0 {
		writeErr(w, 404, "材料不存在")
		return
	}
	a, e := s.m.pg.GetReverseArtifact(tid, aid)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	if a == nil {
		writeErr(w, 404, "材料不存在")
		return
	}
	root, _ := filepath.Abs(filepath.Join(s.m.dir, "tasks", strconv.FormatInt(tid, 10), "reverse", "artifacts"))
	path, _ := filepath.Abs(filepath.Join(s.m.dir, a.Path))
	rel, e := filepath.Rel(root, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		writeErr(w, 404, "材料不存在")
		return
	}
	fi, e := os.Stat(path)
	if e != nil || !fi.Mode().IsRegular() {
		writeErr(w, 404, "材料不存在")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", urlPathEscape(a.Name)))
	http.ServeFile(w, r, path)
}
func urlPathEscape(v string) string { return url.PathEscape(v) }
func (s *Server) reverseConclusionList(w http.ResponseWriter, r *http.Request) {
	tid, _, ok := s.reverseIDs(r)
	if !ok {
		writeErr(w, 404, "逆向任务不存在")
		return
	}
	c, e := s.m.pg.ListReverseConclusions(tid)
	if e != nil {
		writeErr(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, c)
}
