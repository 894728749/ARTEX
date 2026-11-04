package server

import (
	"debug/pe"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Static tools are an explicit allowlist. Adding an upstream family must never
// enable its process-control, shell, device-install or annotation operations.
func reverseStaticToolAllowed(name string) bool {
	for _, allowed := range strings.Fields(`
 inspect_analysis_settings inspect_analysis_view inspect_artifact inspect_binary_layout
 inspect_byte_entropy inspect_pe_resources inspect_pe_load_config inspect_pe_certificates inspect_pe_imports
 inspect_native_exports inspect_elf_notes inspect_go_binary inspect_rust_binary inspect_macho inspect_signature
 inspect_android_package search_android_classes inspect_android_class inspect_android_method trace_android_references
 inspect_managed_artifact inspect_managed_members inspect_managed_native_boundaries compare_managed_members
 verify_managed_native_boundaries project_managed_application_graph project_android_application_graph
 inspect_apk_signature inspect_native_load_image inspect_native_data_type inspect_native_instruction
 resolve_native_call_targets trace_native_values inspect_native_dispatch_metadata
 list_procedures list_segments list_strings list_names procedure_address procedure_assembly procedure_callees
 procedure_callers procedure_info procedure_references procedure_pseudo_code read_function_instructions
 search_bytes read_bytes address_to_file_offset resolve_containing_procedure search_procedures search_strings xrefs
 batch_decompile get_call_graph find_xrefs_to_name binary_overview analyze_function trace_feature trace_call_path
 analyze_javascript_application analyze_web_bundle trace_web_module_imports trace_web_source_location
 trace_application_feature trace_javascript_semantics compare_application_versions compare_source_to_bundle
 compare_javascript_export_shapes open_binary close_binary binary_session get_evidence_bundle
 compare_artifacts compare_functions match_native_functions compare_bundles find_changed_behavior build_call_path
 correlate_static_and_runtime list_unknowns record_unknown update_unknown verify_unknown_resolution
 get_navigation_context inspect_address_context inspect_with_objdump
 `) {
		if name == allowed {
			return true
		}
	}
	return false
}

// The PE CLI directory, rather than the suffix, distinguishes a managed EXE/DLL.
func reverseArtifactFamily(path, format string) (string, error) {
	switch strings.ToLower(format) {
	case "js", "mjs", "cjs":
		return "javascript", nil
	case "apk":
		return "android", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var head [4]byte
	n, _ := f.Read(head[:])
	if n >= 2 && string(head[:2]) == "MZ" {
		image, err := pe.Open(path)
		if err != nil {
			return "", err
		}
		defer image.Close()
		managed := false
		switch h := image.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			managed = h.NumberOfRvaAndSizes > 14 && h.DataDirectory[14].VirtualAddress != 0
		case *pe.OptionalHeader64:
			managed = h.NumberOfRvaAndSizes > 14 && h.DataDirectory[14].VirtualAddress != 0
		}
		if managed {
			return "managed", nil
		}
		return "native", nil
	}
	if n == 4 && (string(head[:]) == "\x7fELF" || string(head[:]) == "\xcf\xfa\xed\xfe" || string(head[:]) == "\xce\xfa\xed\xfe" || string(head[:]) == "\xfe\xed\xfa\xcf" || string(head[:]) == "\xfe\xed\xfa\xce" || string(head[:]) == "\xca\xfe\xba\xbe") {
		return "native", nil
	}
	return "", errors.New("未识别的分析格式；请选择 JS、APK、PE/.NET、ELF 或 Mach-O 材料")
}

func reverseStaticArguments(family, path string) (string, map[string]any) {
	switch family {
	case "javascript":
		return "analyze_javascript_application", map[string]any{"input_path": filepath.Dir(path)}
	case "android":
		return "inspect_android_package", map[string]any{"path": path, "detail": "summary"}
	case "managed":
		return "inspect_managed_artifact", map[string]any{"path": path, "detail": "summary"}
	default:
		return "open_binary", map[string]any{"path": path, "provider_id": "ghidra"}
	}
}

func validateReverseStaticPaths(args any, taskDir string) error {
	switch v := args.(type) {
	case map[string]any:
		for k, item := range v {
			if k == "source_paths" {
				if paths, ok := item.([]any); ok {
					for _, value := range paths {
						if path, ok := value.(string); ok && (filepath.IsAbs(path) || filepath.Clean(path) == ".." || strings.HasPrefix(filepath.Clean(path), ".."+string(filepath.Separator))) {
							return errors.New("source_paths 必须是材料目录内的相对文件路径")
						}
					}
				}
			}
			if path, ok := item.(string); ok && (k == "path" || strings.HasSuffix(k, "_path")) {
				if !filepath.IsAbs(path) {
					return errors.New("分析文件路径必须位于当前任务的绝对工作目录")
				}
				resolved, err := filepath.EvalSymlinks(path)
				if err != nil {
					return errors.New("分析文件不存在或无法解析")
				}
				root, err := filepath.EvalSymlinks(taskDir)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(root, resolved)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return errors.New("分析路径不属于当前逆向任务")
				}
			}
			if err := validateReverseStaticPaths(item, taskDir); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := validateReverseStaticPaths(item, taskDir); err != nil {
				return err
			}
		}
	}
	return nil
}
