package db

import (
	"context"
	"database/sql"
)

// ReconcileIntentDependencies exposes unsuccessful prerequisites instead of
// leaving downstream work waiting forever. Only reverse work is reconciled;
// pentest scheduling and independently blocked work retain their policy.
func (s *ExplorationStore) ReconcileIntentDependencies(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = s.lockExploration(ctx, tx); err != nil {
		return 0, err
	}
	n, err := s.reconcileIntentDependenciesTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func (s *ExplorationStore) reconcileIntentDependenciesTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var total int64
	// Each pass propagates another dependency level. Contracts have at most 32
	// predecessors; a future claim/planning pass continues deeper legacy graphs.
	for range 32 {
		r, err := tx.ExecContext(ctx, `WITH candidates AS (
 SELECT n.id, COALESCE((SELECT jsonb_agg(jsonb_build_object('intent_id',d.value::bigint,'state',COALESCE(p.state,'missing')) ORDER BY d.value::bigint)
 FROM jsonb_array_elements_text(COALESCE(n.payload->'contract'->'depends_on','[]')) d
 LEFT JOIN exploration_nodes p ON p.id=d.value::bigint AND p.exploration_id=n.exploration_id
 WHERE p.id IS NULL OR p.state IN ('blocked','exhausted','stopped','deleted')),'[]') failures,
 NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(n.payload->'contract'->'depends_on','[]')) d
 LEFT JOIN exploration_nodes p ON p.id=d.value::bigint AND p.exploration_id=n.exploration_id WHERE p.id IS NULL OR p.state<>'done') ready
 FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id AND t.kind='reverse'
 WHERE n.exploration_id=$1 AND n.kind='intent' AND (n.state='waiting' OR (n.state='blocked' AND n.blocked_reason='dependency_failed'))
 AND NOT(n.payload ? 'workflow_wait_id') AND COALESCE(n.payload->'contract'->>'remote_assignment_pending','false')<>'true'
 ), desired AS (SELECT *, CASE WHEN failures<>'[]'::jsonb THEN 'blocked' WHEN ready THEN 'open' ELSE 'waiting' END next_state FROM candidates)
 UPDATE exploration_nodes n SET state=d.next_state, blocked_reason=CASE WHEN d.next_state='blocked' THEN 'dependency_failed' END,
 payload=CASE WHEN d.next_state='blocked' THEN n.payload||jsonb_build_object('dependency_failures',d.failures) ELSE n.payload-'dependency_failures' END,
 completed_at=NULL,content_version=content_version+1
 FROM desired d WHERE n.id=d.id AND (n.state<>d.next_state OR COALESCE(n.payload->'dependency_failures','[]')<>d.failures)`, s.expID)
		if err != nil {
			return total, err
		}
		n, _ := r.RowsAffected()
		total += n
		if n == 0 {
			break
		}
	}
	return total, nil
}
