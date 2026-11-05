package collab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Envelope is the stable, transport-neutral command identity sent between peers.
type Envelope struct {
	Version     int             `json:"version"`
	CommandID   string          `json:"command_id"`
	ExecutionID string          `json:"execution_id"`
	Epoch       int64           `json:"epoch"`
	Payload     json.RawMessage `json:"payload"`
}

func (e Envelope) Validate() error {
	if e.Version != 1 || e.CommandID == "" || len(e.CommandID) > 4096 || e.ExecutionID == "" || len(e.ExecutionID) > 4096 || e.Epoch < 0 || len(e.Payload) == 0 || len(e.Payload) > 4<<20 || !json.Valid(e.Payload) {
		return errors.New("invalid collaboration envelope")
	}
	return nil
}

// Outbox persists pending envelopes as individual files; each write is atomic and durable.
type Outbox struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
}

func OpenOutbox(dir string, maxBytes int64) (*Outbox, error) {
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	return &Outbox{dir: dir, maxBytes: maxBytes}, nil
}
func (o *Outbox) file(id string) string {
	return filepath.Join(o.dir, idFileKey(id)+".json")
}
func idFileKey(id string) string { h := sha256.Sum256([]byte(id)); return hex.EncodeToString(h[:]) }
func envelopeHash(e Envelope) string {
	b, _ := json.Marshal(struct {
		Version     int    `json:"version"`
		CommandID   string `json:"command_id"`
		ExecutionID string `json:"execution_id"`
		Epoch       int64  `json:"epoch"`
		Payload     []byte `json:"payload"`
	}{e.Version, e.CommandID, e.ExecutionID, e.Epoch, []byte(e.Payload)})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (o *Outbox) Put(e Envelope) error {
	if err := e.Validate(); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	p := o.file(e.CommandID)
	if old, err := os.ReadFile(p); err == nil {
		var prior Envelope
		if json.Unmarshal(old, &prior) != nil || prior.Validate() != nil || prior.CommandID != e.CommandID || envelopeHash(prior) != envelopeHash(e) {
			return fmt.Errorf("command_id identity conflict: %s", e.CommandID)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	total, err := o.size()
	if err != nil {
		return err
	}
	if total+int64(len(b)) > o.maxBytes {
		return errors.New("outbox size limit exceeded")
	}
	f, err := os.CreateTemp(o.dir, ".pending-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = persistRename(tmp, p); err != nil {
		return err
	}
	return syncDir(o.dir)
}
func (o *Outbox) Ack(id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	p := o.file(id)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored Envelope
	if json.Unmarshal(b, &stored) != nil || stored.Validate() != nil || stored.CommandID != id {
		return errors.New("outbox command_id hash collision or corrupt record; refusing ack")
	}
	err = os.Remove(p)
	if err != nil {
		return err
	}
	return syncDir(o.dir)
}
func (o *Outbox) Pending() ([]Envelope, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return nil, err
	}
	out := []Envelope{}
	for _, x := range entries {
		if x.IsDir() || filepath.Ext(x.Name()) != ".json" {
			continue
		}
		b, e := os.ReadFile(filepath.Join(o.dir, x.Name()))
		if e != nil {
			return nil, e
		}
		var v Envelope
		if json.Unmarshal(b, &v) != nil || v.Validate() != nil || o.file(v.CommandID) != filepath.Join(o.dir, x.Name()) {
			return nil, fmt.Errorf("corrupt outbox record %s", x.Name())
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CommandID < out[j].CommandID })
	return out, nil
}
func (o *Outbox) size() (int64, error) {
	es, e := os.ReadDir(o.dir)
	if e != nil {
		return 0, e
	}
	var n int64
	for _, x := range es {
		if x.IsDir() {
			continue
		}
		i, e := x.Info()
		if e != nil {
			return 0, e
		}
		n += i.Size()
	}
	return n, nil
}

// Inbox detects command replay and rejects a stable ID reused with different content.
type Inbox struct {
	mu       sync.Mutex
	hashes   map[string]string
	dir      string
	maxBytes int64
}

func NewInbox() *Inbox { return &Inbox{hashes: map[string]string{}} }

// OpenInbox loads durable deduplication records. Records use 0600 files and are fsynced before Accept succeeds.
func OpenInbox(dir string, maxBytes int64) (*Inbox, error) {
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	i := &Inbox{hashes: map[string]string{}, dir: dir, maxBytes: maxBytes}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, x := range entries {
		if x.IsDir() || filepath.Ext(x.Name()) != ".json" {
			continue
		}
		b, e := os.ReadFile(filepath.Join(dir, x.Name()))
		if e != nil {
			return nil, e
		}
		var r struct {
			CommandID string `json:"command_id"`
			Hash      string `json:"identity_hash"`
		}
		if json.Unmarshal(b, &r) != nil {
			return nil, fmt.Errorf("corrupt inbox record %s", x.Name())
		}
		_, hashErr := hex.DecodeString(r.Hash)
		if r.CommandID == "" || len(r.CommandID) > 4096 || len(r.Hash) != 64 || hashErr != nil || filepath.Base(filepath.Join(dir, idFileKey(r.CommandID)+".json")) != x.Name() {
			return nil, fmt.Errorf("corrupt inbox record %s", x.Name())
		}
		i.hashes[r.CommandID] = r.Hash
	}
	return i, nil
}

// Accept returns true only for a new command. Callers should persist their own execution result before acking.
func (i *Inbox) Accept(e Envelope) (bool, error) {
	if err := e.Validate(); err != nil {
		return false, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	h := envelopeHash(e)
	if prior, ok := i.hashes[e.CommandID]; ok {
		if prior != h {
			return false, fmt.Errorf("command_id identity conflict: %s", e.CommandID)
		}
		return false, nil
	}
	if i.dir != "" {
		rec, _ := json.Marshal(struct {
			CommandID string `json:"command_id"`
			Hash      string `json:"identity_hash"`
		}{e.CommandID, h})
		total, err := directorySize(i.dir)
		if err != nil {
			return false, err
		}
		if total+int64(len(rec)) > i.maxBytes {
			return false, errors.New("inbox size limit exceeded")
		}
		p := filepath.Join(i.dir, idFileKey(e.CommandID)+".json")
		if old, readErr := os.ReadFile(p); readErr == nil {
			var record struct {
				CommandID string `json:"command_id"`
				Hash      string `json:"identity_hash"`
			}
			if json.Unmarshal(old, &record) != nil || record.CommandID != e.CommandID {
				return false, errors.New("inbox command_id hash collision or corrupt record")
			}
			if record.Hash != h {
				return false, fmt.Errorf("command_id identity conflict: %s", e.CommandID)
			}
			i.hashes[e.CommandID] = h
			return false, nil
		} else if !os.IsNotExist(readErr) {
			return false, readErr
		}
		f, err := os.CreateTemp(i.dir, ".pending-*")
		if err != nil {
			return false, err
		}
		tmp := f.Name()
		defer os.Remove(tmp)
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(rec)
		}
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err == nil {
			err = ce
		}
		if err != nil {
			return false, err
		}
		if err = persistRename(tmp, p); err != nil {
			return false, err
		}
		if err = syncDir(i.dir); err != nil {
			return false, err
		}
	}
	i.hashes[e.CommandID] = h
	return true, nil
}

func directorySize(dir string) (int64, error) {
	es, e := os.ReadDir(dir)
	if e != nil {
		return 0, e
	}
	var n int64
	for _, x := range es {
		if x.IsDir() {
			continue
		}
		i, e := x.Info()
		if e != nil {
			return 0, e
		}
		n += i.Size()
	}
	return n, nil
}
