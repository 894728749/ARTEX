"use client";

import * as React from "react";

import { api, createAPI, http } from "@/lib/api";
import { createNativeAPI, nativeApi } from "@/lib/native-api";

type TaskView = {
  api: typeof api;
  nativeApi: ReturnType<typeof createNativeAPI>;
  readOnly: boolean;
  findingHref: (id: string | number, contextTask?: string) => string;
  taskHref: (id: string | number) => string;
  backHref: string;
};

const TaskViewContext = React.createContext<TaskView>({
  api,
  nativeApi,
  readOnly: false,
  findingHref: (id, task) =>
    `/function/findings/detail?id=${encodeURIComponent(id)}${task ? `&context_task=${encodeURIComponent(task)}` : ""}`,
  taskHref: (id) => `/function/tasks/detail?id=${encodeURIComponent(id)}`,
  backHref: "/function/findings",
});

export function useTaskView() {
  return React.useContext(TaskViewContext);
}

export function MemberTaskViewProvider({
  team,
  task,
  onAccessLost,
  children,
}: {
  team: string;
  task: string;
  onAccessLost: () => void;
  children: React.ReactNode;
}) {
  const lost = React.useRef(onAccessLost);
  lost.current = onAccessLost;
  const value = React.useMemo<TaskView>(() => {
    const base = `/teams/${encodeURIComponent(team)}/tasks/${encodeURIComponent(task)}/native`;
    const readURL = (path: string) => `${base}?${new URLSearchParams({ path })}`;
    const request: typeof http = async <T,>(path: string, init?: RequestInit): Promise<T> => {
      if (init?.method && init.method !== "GET") throw new Error("当前视图仅供查看任务资料。");
      try {
        return await http<T>(readURL(path), init);
      } catch (error) {
        const status = (error as { status?: number })?.status;
        if (status === 401 || status === 403) lost.current();
        throw error;
      }
    };
    const taskHref = (id: string | number) =>
      `/function/team/task/?team=${encodeURIComponent(team)}&id=${encodeURIComponent(id)}`;
    const backHref = `${taskHref(task)}&tab=findings`;
    return {
      api: createAPI(request, readURL),
      nativeApi: createNativeAPI(request),
      readOnly: true,
      taskHref,
      backHref,
      findingHref: (id) => `${backHref}&finding=${encodeURIComponent(id)}`,
    };
  }, [team, task]);
  return <TaskViewContext.Provider value={value}>{children}</TaskViewContext.Provider>;
}
