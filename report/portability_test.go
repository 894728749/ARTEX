package report

import "testing"

func TestValidatePortableReportRejectsInternalIDs(t *testing.T) {
	for _, input := range []string{
		"ARTEX task_id=42",
		"worker #7",
		"平台 finding_id: 18",
		"本任务 node 编号：3",
		"平台 traffic id #91",
	} {
		t.Run(input, func(t *testing.T) {
			if err := ValidatePortableReport("## 证据\n" + input); err == nil {
				t.Fatalf("expected internal identifier to be rejected: %q", input)
			}
		})
	}
}

func TestValidatePortableReportRejectsMachinePaths(t *testing.T) {
	for _, input := range []string{
		"日志见 C:\\Users\\alice\\Desktop\\trace.txt",
		"本机文件：[trace](file:///home/alice/run/output.txt)",
		"工作目录 /home/codex/project/tasks/4/i8",
	} {
		t.Run(input, func(t *testing.T) {
			if err := ValidatePortableReport(input); err == nil {
				t.Fatalf("expected local machine path to be rejected: %q", input)
			}
		})
	}
}

func TestValidatePortableReportKeepsTargetEvidence(t *testing.T) {
	input := `## 复现步骤
1. POST /api/v1/login HTTP/1.1
2. 请求目标文件 /etc/passwd
3. 目标地址 192.0.2.10:8080，版本 1.2.3，CVE-2025-1234
4. 请求体 {"task_id":42,"node_id":3}；目标文件 /home/app/data.db、/tmp/cache、C:\Users\service\config.ini
5. 运行 ./poc.sh --url https://example.test/api/login

证据：HTTP/1.1 200 OK`
	if err := ValidatePortableReport(input); err != nil {
		t.Fatalf("valid target evidence must be retained: %v", err)
	}
}

func TestValidatePortableReportDoesNotRewriteReport(t *testing.T) {
	input := "## 证据\nworker #7"
	_ = ValidatePortableReport(input)
	if input != "## 证据\nworker #7" {
		t.Fatal("validator must not mutate the report")
	}
}
