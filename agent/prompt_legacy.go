package agent

// LegacyBuiltinPromptHashes identifies exact shipped defaults from repository history.
// Only system-owned templates matching these hashes may be automatically upgraded.
// Unknown templates and user-owned versions are preserved by the database synchronizer.
func LegacyBuiltinPromptHashes(key string) []string {
	return map[string][]string{
		"goals": {
			"72a7a0159443b41dde29dfba8a3de6a2c8a15b273935495a7b88561fa708aa68", // 5c0dbd4
		},
		"mainagent": {
			"12bb69ee0886c4fb9beb936d882021a91104860f1da69a5e3eda3d9e345cd399", // 5c0dbd4
		},
		"planner": {
			"14e163f4a44da9fee20a214048a607adc3659b2025275569eb512532ca8c15d5", // 5c0dbd4
		},
	}[key]
}
