package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type FindingRelation struct {
	ID        int64  `json:"id"`
	Source    int64  `json:"source"`
	Target    int64  `json:"target"`
	Kind      string `json:"kind"`
	Rationale string `json:"rationale"`
	Evidence  string `json:"evidence"`
	Status    string `json:"status"`
}

type FindingGraphNode struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

func (d *DB) FindingGraph(taskID int64) ([]FindingGraphNode, []FindingRelation, error) {
	nodes := []FindingGraphNode{}
	edges := []FindingRelation{}
	rows, err := d.Query(`SELECT id,COALESCE(NULLIF(name,''),vulnclass),severity,status FROM findings WHERE task_id=$1 AND merged_into IS NULL ORDER BY id`, taskID)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var n FindingGraphNode
		if err = rows.Scan(&n.ID, &n.Name, &n.Severity, &n.Status); err != nil {
			rows.Close()
			return nil, nil, err
		}
		nodes = append(nodes, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = d.Query(`SELECT r.id,r.source_id,r.target_id,r.kind,r.rationale,r.evidence,r.status FROM finding_relations r JOIN findings a ON a.id=r.source_id JOIN findings b ON b.id=r.target_id WHERE r.task_id=$1 AND a.merged_into IS NULL AND b.merged_into IS NULL ORDER BY r.id`, taskID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e FindingRelation
		if err = rows.Scan(&e.ID, &e.Source, &e.Target, &e.Kind, &e.Rationale, &e.Evidence, &e.Status); err != nil {
			return nil, nil, err
		}
		edges = append(edges, e)
	}
	return nodes, edges, rows.Err()
}

func (d *DB) SaveFindingRelation(ctx context.Context, taskID int64, r FindingRelation) (int64, error) {
	if r.Source <= 0 || r.Target <= 0 || r.Source == r.Target {
		return 0, errors.New("请选择两个不同的漏洞")
	}
	switch r.Kind {
	case "prerequisite", "enables", "supports", "contradicts":
	default:
		return 0, errors.New("无效关系类型")
	}
	if r.Status != "proposed" && r.Status != "verified" {
		return 0, errors.New("关系状态必须为 proposed 或 verified")
	}
	if strings.TrimSpace(r.Rationale) == "" || strings.TrimSpace(r.Evidence) == "" {
		return 0, errors.New("必须说明关系理由和证据；未验证需说明待验证内容")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// Serialize relation changes with consolidation for this task.
	if _, err = tx.ExecContext(ctx, `SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, taskID); err != nil {
		return 0, err
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE id IN ($1,$2) AND task_id=$3 AND merged_into IS NULL`, r.Source, r.Target, taskID).Scan(&n); err != nil {
		return 0, err
	}
	if n != 2 {
		return 0, errors.New("关系仅允许关联同一任务内尚未归并的漏洞")
	}
	if r.Kind == "prerequisite" || r.Kind == "enables" {
		var cycle bool
		err = tx.QueryRowContext(ctx, `WITH RECURSIVE reach(id) AS (SELECT target_id FROM finding_relations WHERE task_id=$1 AND source_id=$2 AND kind IN ('prerequisite','enables') UNION SELECT r.target_id FROM finding_relations r JOIN reach x ON r.source_id=x.id WHERE r.task_id=$1 AND r.kind IN ('prerequisite','enables')) SELECT EXISTS(SELECT 1 FROM reach WHERE id=$3)`, taskID, r.Target, r.Source).Scan(&cycle)
		if err != nil {
			return 0, err
		}
		if cycle {
			return 0, errors.New("依赖关系不能形成循环")
		}
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO finding_relations(task_id,source_id,target_id,kind,rationale,evidence,status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(task_id,source_id,target_id,kind) DO UPDATE SET rationale=EXCLUDED.rationale,evidence=EXCLUDED.evidence,status=EXCLUDED.status RETURNING id`, taskID, r.Source, r.Target, r.Kind, r.Rationale, r.Evidence, r.Status).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

type ConsolidateFindingsInput struct {
	CanonicalID int64            `json:"canonical_id"`
	SourceIDs   []int64          `json:"source_ids"`
	Name        string           `json:"name"`
	Summary     string           `json:"summary"`
	Severity    string           `json:"severity"`
	Reason      string           `json:"reason"`
	Versions    map[string]int64 `json:"versions"`
}

// ConsolidateFindings retains source rows, retests, original reports and an audit
// snapshot. Only the canonical row is shown in ordinary lists. All evidence
// changes use the same transaction lock as evidence binding/report generation.
func (d *DB) ConsolidateFindings(ctx context.Context, taskID, reviewID int64, in ConsolidateFindingsInput) (err error) {
	if in.CanonicalID <= 0 || len(in.SourceIDs) == 0 || len(in.SourceIDs) > 50 {
		return errors.New("需要一个主记录和 1–50 个来源记录")
	}
	if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.Summary) == "" || strings.TrimSpace(in.Reason) == "" || !ValidSeverity(in.Severity) {
		return errors.New("需给出统一名称、摘要、证据支持的等级和同根因判断理由")
	}
	ids := append([]int64{in.CanonicalID}, in.SourceIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i, id := range ids {
		if id <= 0 || (i > 0 && ids[i-1] == id) {
			return errors.New("漏洞 ID 不能重复")
		}
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		var originals []json.RawMessage
		assets := map[int64]bool{}
		var evidence strings.Builder
		var canonicalNode *int64
		for _, id := range ids {
			var tid, merged, node *int64
			var version int64
			var name, body, raw, assetJSON string
			err := tx.QueryRowContext(ctx, `SELECT task_id,merged_into,node_id,evidence_version,name,evidence,asset_ids::text,to_jsonb(findings)::text FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&tid, &merged, &node, &version, &name, &body, &assetJSON, &raw)
			if err != nil {
				return err
			}
			if tid == nil || *tid != taskID || merged != nil {
				return errors.New("只能归并同一任务内未归并的漏洞")
			}
			v, ok := in.Versions[strconv.FormatInt(id, 10)]
			if !ok || v != version {
				return errors.New("漏洞证据版本变化或缺失，请重新读取后判断")
			}
			originals = append(originals, json.RawMessage(raw))
			var aa []int64
			_ = json.Unmarshal([]byte(assetJSON), &aa)
			for _, a := range aa {
				assets[a] = true
			}
			fmt.Fprintf(&evidence, "### %s\n\n%s\n\n", name, body)
			if id == in.CanonicalID {
				canonicalNode = node
			}
		}
		// A dependency means distinct conditions. Do not erase an explicitly
		// recorded chain by collapsing its endpoints into a single finding.
		for _, a := range ids {
			for _, b := range ids {
				if a == b {
					continue
				}
				var exists bool
				if err := tx.QueryRowContext(ctx, `WITH RECURSIVE reach(id) AS (SELECT target_id FROM finding_relations WHERE task_id=$3 AND source_id=$1 AND kind IN ('prerequisite','enables') UNION SELECT r.target_id FROM finding_relations r JOIN reach x ON r.source_id=x.id WHERE r.task_id=$3 AND r.kind IN ('prerequisite','enables')) SELECT EXISTS(SELECT 1 FROM reach WHERE id=$2) OR EXISTS(SELECT 1 FROM finding_relations WHERE task_id=$3 AND source_id=$1 AND target_id=$2 AND kind='contradicts')`, a, b, taskID).Scan(&exists); err != nil {
					return err
				}
				if exists {
					return errors.New("候选记录存在依赖或矛盾关系，请先复核关系，不能直接归并")
				}
			}
		}
		aa := []int64{}
		for a := range assets {
			aa = append(aa, a)
		}
		sort.Slice(aa, func(i, j int) bool { return aa[i] < aa[j] })
		aJSON, _ := json.Marshal(aa)
		snap, _ := json.Marshal(originals)
		sourceJSON, _ := json.Marshal(in.SourceIDs)
		if _, err := tx.ExecContext(ctx, `INSERT INTO finding_consolidations(task_id,review_id,canonical_id,source_ids,reason,snapshot) VALUES($1,NULLIF($2,0),$3,$4,$5,$6)`, taskID, reviewID, in.CanonicalID, string(sourceJSON), in.Reason, string(snap)); err != nil {
			return err
		}
		for _, id := range in.SourceIDs {
			if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=payload || jsonb_build_object('merged_into',$2::bigint) WHERE id=(SELECT node_id FROM findings WHERE id=$1)`, id, in.CanonicalID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET merged_into=$2 WHERE id=$1`, id, in.CanonicalID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET merged_into=$2 WHERE merged_into=$1`, id, in.CanonicalID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position) SELECT $1,snapshot_id,role,note,position+(SELECT COALESCE(max(position),0)+1 FROM finding_traffic_bindings WHERE finding_id=$1) FROM finding_traffic_bindings WHERE finding_id=$2 ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, in.CanonicalID, id); err != nil {
				return err
			}
			if canonicalNode != nil {
				if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id) SELECT $1,asset_id FROM exploration_anchors WHERE node_id=(SELECT node_id FROM findings WHERE id=$2) ON CONFLICT DO NOTHING`, *canonicalNode, id); err != nil {
					return err
				}
			}
			// Preserve original edges for audit, copy their meaning to the new
			// representative and require verification again after identity changes.
			if _, err := tx.ExecContext(ctx, `INSERT INTO finding_relations(task_id,source_id,target_id,kind,rationale,evidence,status) SELECT task_id,CASE WHEN source_id=$2 THEN $1 ELSE source_id END,CASE WHEN target_id=$2 THEN $1 ELSE target_id END,kind,rationale,evidence,'proposed' FROM finding_relations WHERE (source_id=$2 OR target_id=$2) AND source_id<>$1 AND target_id<>$1 ON CONFLICT DO NOTHING`, in.CanonicalID, id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET name=$2,summary=$3,severity=$4,evidence=$5,asset_ids=$6,evidence_version=evidence_version+1 WHERE id=$1`, in.CanonicalID, in.Name, in.Summary, in.Severity, evidence.String(), string(aJSON)); err != nil {
			return err
		}
		if canonicalNode != nil {
			payload, _ := json.Marshal(map[string]any{"name": in.Name, "summary": in.Summary, "severity": in.Severity, "evidence": map[string]any{"poc": evidence.String()}})
			if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=payload || $2::jsonb WHERE id=$1`, *canonicalNode, string(payload)); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO finding_report_rewrites(finding_id,evidence_version) SELECT id,evidence_version FROM findings WHERE id=$1 ON CONFLICT DO NOTHING`, in.CanonicalID)
		if err != nil {
			return err
		}
		return nil
	})
}

type FindingReviewStatus struct {
	Enabled       bool   `json:"enabled"`
	BatchSize     int    `json:"batch_size"`
	PendingCount  int    `json:"pending_count"`
	Running       bool   `json:"running"`
	LastError     string `json:"last_error,omitempty"`
	ReportPending int    `json:"report_pending"`
	ReportError   string `json:"report_error,omitempty"`
}

func (d *DB) FindingReviewStatus(taskID int64) (out FindingReviewStatus, err error) {
	if _, err = d.Exec(`INSERT INTO finding_review_state(task_id) VALUES($1) ON CONFLICT DO NOTHING`, taskID); err != nil {
		return
	}
	err = d.QueryRow(`SELECT enabled,batch_size,(SELECT count(*) FROM findings f WHERE f.task_id=s.task_id AND f.merged_into IS NULL AND f.id>s.reviewed_through),EXISTS(SELECT 1 FROM finding_reviews r WHERE r.task_id=s.task_id AND r.status='running'),last_error FROM finding_review_state s WHERE task_id=$1`, taskID).Scan(&out.Enabled, &out.BatchSize, &out.PendingCount, &out.Running, &out.LastError)
	if err == nil {
		err = d.QueryRow(`SELECT count(*) FILTER(WHERE j.status IN ('pending','running')),COALESCE(string_agg(NULLIF(j.last_error,''),'; ') FILTER(WHERE j.status='failed'),'') FROM finding_report_rewrites j JOIN findings f ON f.id=j.finding_id WHERE f.task_id=$1 AND f.merged_into IS NULL AND j.evidence_version=f.evidence_version`, taskID).Scan(&out.ReportPending, &out.ReportError)
	}
	return
}

// BeginFindingReview is persisted and deduplicated across trigger ticks.
func (d *DB) BeginFindingReview(ctx context.Context, taskID int64, manual bool) (reviewID, cutoff int64, err error) {
	_, err = d.FindingReviewStatus(taskID)
	if err != nil {
		return
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var enabled bool
	var batch, pending int
	var through, attempt int64
	if !manual {
		var paused bool
		var status string
		err = tx.QueryRowContext(ctx, `SELECT paused,status FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, taskID).Scan(&paused, &status)
		if err != nil {
			return
		}
		if paused {
			return 0, 0, nil
		}
		// Terminal tasks flush a partial batch once. The attempted watermark below
		// still prevents repeated paid retries after failure or interruption.
		if IsTerminal(status) {
			batch = 1
		}
	}
	tailBatch := batch
	err = tx.QueryRowContext(ctx, `SELECT enabled,batch_size,reviewed_through,attempted_through FROM finding_review_state WHERE task_id=$1 FOR UPDATE`, taskID).Scan(&enabled, &batch, &through, &attempt)
	if err != nil {
		return
	}
	if tailBatch == 1 {
		batch = 1
	}
	err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE id>$2),COALESCE(max(id),0) FROM findings WHERE task_id=$1 AND merged_into IS NULL`, taskID, through).Scan(&pending, &cutoff)
	if err != nil {
		return
	}
	if cutoff == 0 || (!manual && (!enabled || pending < batch || cutoff <= attempt)) {
		return 0, cutoff, nil
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO finding_reviews(task_id,cutoff_id,status) VALUES($1,$2,'running') ON CONFLICT(task_id) WHERE status='running' DO NOTHING RETURNING id`, taskID, cutoff).Scan(&reviewID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, cutoff, nil
	}
	if err != nil {
		return
	}
	_, err = tx.ExecContext(ctx, `UPDATE finding_review_state SET attempted_through=$2,last_error='' WHERE task_id=$1`, taskID, cutoff)
	if err != nil {
		return
	}
	err = tx.Commit()
	return
}

func (d *DB) FindingReviewContext(ctx context.Context, convID int64) (id, taskID, cutoff int64, err error) {
	err = d.QueryRowContext(ctx, `SELECT id,task_id,cutoff_id FROM finding_reviews WHERE conversation_id=$1 AND status='running'`, convID).Scan(&id, &taskID, &cutoff)
	return
}

func (d *DB) FinishFindingReview(ctx context.Context, id int64, success bool, summary string) error {
	if strings.TrimSpace(summary) == "" {
		return errors.New("必须保存检查结论")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var taskID, cutoff int64
	status := "failed"
	if success {
		status = "completed"
	}
	err = tx.QueryRowContext(ctx, `UPDATE finding_reviews SET status=$2,summary=$3,finished_at=now() WHERE id=$1 AND status='running' RETURNING task_id,cutoff_id`, id, status, summary).Scan(&taskID, &cutoff)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if success {
		_, err = tx.ExecContext(ctx, `UPDATE finding_review_state SET reviewed_through=GREATEST(reviewed_through,$2),last_error='' WHERE task_id=$1`, taskID, cutoff)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE finding_review_state SET last_error=$2 WHERE task_id=$1`, taskID, summary)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
