import { http } from "@/lib/api";

export type NativeMode = "analysis" | "pwn";
export interface NativeArtifactBinding {
  artifact_id: number;
  sha256: string;
  name: string;
}
export interface NativeReplayPlan {
  version: 1 | 2;
  input_mode: "stdin" | "file";
  artifact_sha256?: string;
  image?: string;
  policy_revision?: number;
  parent_case_id?: number;
  target?: {
    dependencies?: NativeArtifactBinding[];
    loader?: NativeArtifactBinding;
    harness?: NativeArtifactBinding;
  };
  assertion?: { type: "exit_code" | "signal" | "stdout_contains_base64"; value?: number; data_base64?: string };
}
export interface NativeCase {
  id: number | string;
  artifact_id: number;
  profile_id: string;
  argv: string[];
  input_base64: string;
  expected_exit?: number;
  expected_signal?: number;
  replay_plan?: NativeReplayPlan;
  title: string;
  sha256: string;
  created_at: string;
}
export interface NativeRun {
  run_id: number;
  task_id: number;
  artifact_id: number;
  intent_id: number;
  case_id?: number | string;
  config_revision: number;
  mode: "exec" | "debug" | "replay";
  target_state: string;
  result_path?: string;
  observation: Record<string, unknown>;
}
export interface NativeState {
  config: { mode: NativeMode; revision: number };
  cases: NativeCase[];
  runs: NativeRun[];
}

export const createNativeAPI = (request: typeof http) => ({
  get: (taskId: string) => request<NativeState>(`/tasks/${encodeURIComponent(taskId)}/reverse/native`),
  setMode: (taskId: string, mode: NativeMode) =>
    request<NativeState["config"]>(`/tasks/${encodeURIComponent(taskId)}/reverse/native`, {
      method: "PUT",
      body: JSON.stringify({ mode }),
    }),
  inspect: (taskId: string, artifactId: number) =>
    request<Record<string, unknown>>(
      `/tasks/${encodeURIComponent(taskId)}/reverse/native/inspect?artifact_id=${artifactId}`,
    ),
  doctor: (taskId: string, profileId: string) =>
    request<{ available: boolean; observation: Record<string, unknown> }>(
      `/tasks/${encodeURIComponent(taskId)}/reverse/native/doctor?profile_id=${encodeURIComponent(profileId)}`,
    ),
});
export const nativeApi = createNativeAPI(http);
