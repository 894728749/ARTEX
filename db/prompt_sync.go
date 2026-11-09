package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

// SyncBuiltinPrompt advances an agent's prompt only when its current version is
// still a known built-in default. The hash marker and prompt change commit atomically.
func (d *DB) SyncBuiltinPrompt(agentID int64, template string, legacyHashes []string) (bool, error) {
	if template == "" {
		return false, errors.New("empty built-in prompt template")
	}
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	cur, err := lockAgentPrompt(tx, agentID)
	if err != nil {
		return false, err
	}
	newHash := promptHash(template)
	if !cur.Valid {
		if _, err = appendAgentPrompt(tx, agentID, template, "内置默认", "system"); err != nil {
			return false, err
		}
		if err = setPromptDefaultHash(tx, agentID, newHash); err != nil {
			return false, err
		}
		if err = tx.Commit(); err != nil {
			return false, err
		}
		return true, nil
	}
	var current, updatedBy string
	if err = tx.QueryRow(`SELECT template_text,COALESCE(updated_by,'') FROM agent_prompts WHERE id=$1`, cur.Int64).Scan(&current, &updatedBy); err != nil {
		return false, err
	}
	var previous string
	err = tx.QueryRow(`SELECT template_hash FROM agent_prompt_defaults WHERE agent_id=$1`, agentID).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	appended := false
	if current == template {
		// Already at this template; mark it known without creating duplicate history.
	} else if updatedBy == "system" && (promptHash(current) == previous || containsString(legacyHashes, promptHash(current))) {
		if _, err = appendAgentPrompt(tx, agentID, template, "内置提示词更新", "system"); err != nil {
			return false, err
		}
		appended = true
	}
	if err = setPromptDefaultHash(tx, agentID, newHash); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return appended, nil
}

func promptHash(template string) string {
	sum := sha256.Sum256([]byte(template))
	return hex.EncodeToString(sum[:])
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func setPromptDefaultHash(tx *sql.Tx, agentID int64, hash string) error {
	_, err := tx.Exec(`INSERT INTO agent_prompt_defaults(agent_id,template_hash) VALUES ($1,$2) ON CONFLICT(agent_id) DO UPDATE SET template_hash=EXCLUDED.template_hash`, agentID, hash)
	return err
}
