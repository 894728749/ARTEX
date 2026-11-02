package report

import (
	"fmt"
	"regexp"
)

// These patterns intentionally target explicit ARTEX identifiers and common
// local execution-machine paths. They do not reject ordinary numbers, URLs,
// API routes, or paths that may belong to the target application.
var (
	internalIDReference  = regexp.MustCompile(`(?i)(?:ARTEX|平台内部|平台|本任务|本次任务)[^\n]{0,20}\b(?:task|worker|finding|node|traffic)(?:[_ -]?(?:id|编号))?\s*(?:["']\s*)?(?:[:=：]\s*)?#?\s*\d+\b|\b(?:worker|finding|node|traffic)\s+#\s*\d+\b`)
	fileURL              = regexp.MustCompile(`(?i)\bfile://(?:localhost/)?(?:[a-z]:[/\\]|/)`)
	machinePathReference = regexp.MustCompile(`(?im)(?:本机|执行机|工作目录|日志见|附件见|local file|working directory)[^\n]{0,40}(?:[a-z]:[\\/]|/(?:home|Users|mnt|tmp|var/tmp|workspace|workspaces)/)[^\s<>"']+`)
)

// ValidatePortableReport rejects only clear references to ARTEX's internal
// numeric handles or the report-generating machine's local filesystem. It
// never rewrites a report: callers can show the reason and let the author fix
// the source while retaining real evidence.
func ValidatePortableReport(markdown string) error {
	if internalIDReference.MatchString(markdown) {
		return fmt.Errorf("报告中包含平台内部 task/worker/finding/node/traffic 数字编号；请改用证据用途名称及必要的证据内容引用，保留目标系统自身的编号")
	}
	if fileURL.MatchString(markdown) || machinePathReference.MatchString(markdown) {
		return fmt.Errorf("报告中包含执行机本地文件链接或绝对路径；请改用报告内的相对文件名/用途说明，保留目标系统路径和请求/API 路径")
	}
	return nil
}
