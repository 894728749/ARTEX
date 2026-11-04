package db

import (
	"database/sql"
)

// LatestIntentOutput returns the preferred output for a local intent. A result
// record takes precedence over text records; within each kind the newest row wins.
func (s *ExplorationStore) LatestIntentOutput(id int64) (*Activity, error) {
	var a Activity
	err := s.db.QueryRow(`
SELECT a.id, a.node_id, COALESCE(a.worker,''), a.kind, COALESCE(a.tool,''),
       COALESCE(a.tool_use_id,''), a.is_error, COALESCE(a.summary,''),
       COALESCE(a.detail,''), a.created_at
FROM exploration_nodes n
JOIN activity a ON a.node_id=n.id AND a.exploration_id=n.exploration_id
WHERE n.exploration_id=$1 AND n.id=$2 AND n.kind='intent'
  AND a.kind IN ('result','text')
ORDER BY CASE WHEN a.kind='result' THEN 0 ELSE 1 END, a.id DESC
LIMIT 1`, s.expID, id).Scan(&a.ID, &a.NodeID, &a.Worker, &a.Kind, &a.Tool, &a.ToolUseID, &a.IsError, &a.Summary, &a.Detail, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// LatestIntentOutputWithSources permits output from local intents and directly
// related source tasks. Inherited output is visible only after its intent is terminal.
func (s *ExplorationStore) LatestIntentOutputWithSources(id int64) (*Activity, error) {
	local, err := s.GetNode(id)
	if err != nil {
		return nil, err
	}
	if local != nil {
		if local.Kind != KindIntent {
			return nil, nil
		}
		return s.LatestIntentOutput(id)
	}
	sources, err := s.DirectSourceStores()
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		node, nodeErr := source.Store.GetNode(id)
		if nodeErr != nil {
			return nil, nodeErr
		}
		if node == nil || node.Kind != KindIntent || !inheritedIntentTerminal(node.State) {
			continue
		}
		out, outErr := source.Store.LatestIntentOutput(id)
		if outErr != nil || out == nil {
			return out, outErr
		}
		out.SourceTaskID = source.Task.TaskID
		out.Inherited = true
		return out, nil
	}
	return nil, nil
}

// ListRunningIntents returns every local intent in running state, without a
// recent-node window.
func (s *ExplorationStore) ListRunningIntents() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND state='running' ORDER BY id DESC`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// CountKind returns the exact count of local nodes of kind, excluding merged findings.
func (s *ExplorationStore) CountKind(kind string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM exploration_nodes
WHERE exploration_id=$1 AND kind=$2
  AND NOT (kind='finding' AND payload ? 'merged_into')`, s.expID, kind).Scan(&n)
	return n, err
}
