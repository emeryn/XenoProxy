/** Administration API. */

import { api } from '@/lib/api-client';
import type {
  AuditEvent,
  GroupRecord,
  HealthCheckResult,
  Page,
  Playbook,
  Plugin,
  PluginType,
  Role,
  UserCreated,
  UserDetail,
} from '@/lib/types';

export interface UserPayload {
  username: string;
  display_name?: string | null;
  email?: string | null;
  role: Role;
  group_ids: string[];
  /** Left out, a strong password is generated and returned once. */
  password?: string | null;
}

export interface GroupPayload {
  name: string;
  description: string;
  is_default: boolean;
  require_mfa: boolean;
  external_names: string[];
  grants_admin: boolean;
}

export interface PluginConfigPatch {
  enabled?: boolean;
  timeout_seconds?: number;
  cache_ttl_seconds?: number;
  options?: Record<string, unknown>;
}

export interface PlaybookPayload {
  name: string;
  description: string;
  observable_types: string[];
  analyzers: string[];
  connectors: string[];
  pivots: string[];
  enabled: boolean;
}

export const adminApi = {
  /** Every plugin, or only those of one type. */
  plugins: (pluginType?: PluginType) =>
    api.get<Plugin[]>('/admin/plugins', pluginType ? { plugin_type: pluginType } : undefined),
  patchPlugin: (name: string, patch: PluginConfigPatch) =>
    api.patch<Plugin>(`/admin/plugins/${name}`, patch),
  healthcheck: (name: string) =>
    api.post<HealthCheckResult>(`/admin/plugins/${name}/healthcheck`),
  setSecret: (name: string, secret: string, value: string) =>
    api.put<{ message: string; details: { hint?: string } }>(
      `/admin/plugins/${name}/secrets/${secret}`,
      { value },
    ),
  deleteSecret: (name: string, secret: string) =>
    api.delete<{ message: string }>(`/admin/plugins/${name}/secrets/${secret}`),

  playbooks: () => api.get<Playbook[]>('/playbooks'),
  createPlaybook: (payload: PlaybookPayload) => api.post<Playbook>('/admin/playbooks', payload),
  updatePlaybook: (id: string, payload: PlaybookPayload) =>
    api.put<Playbook>(`/admin/playbooks/${id}`, payload),
  deletePlaybook: (id: string) => api.delete<{ message: string }>(`/admin/playbooks/${id}`),

  // --- accounts ---
  users: () => api.get<UserDetail[]>('/admin/users'),
  createUser: (payload: UserPayload) => api.post<UserCreated>('/admin/users', payload),
  updateUser: (
    id: string,
    patch: Partial<Pick<UserPayload, 'display_name' | 'email' | 'role'>> & {
      is_active?: boolean;
    },
  ) => api.patch<UserDetail>(`/admin/users/${id}`, patch),
  setUserGroups: (id: string, groupIds: string[]) =>
    api.put<UserDetail>(`/admin/users/${id}/groups`, { group_ids: groupIds }),
  resetUserPassword: (id: string) =>
    api.post<UserCreated>(`/admin/users/${id}/reset-password`),
  clearUserMfa: (id: string) =>
    api.post<{ message: string }>(`/admin/users/${id}/clear-mfa`),
  deleteUser: (id: string) => api.delete<{ message: string }>(`/admin/users/${id}`),

  // --- groups ---
  groups: () => api.get<GroupRecord[]>('/admin/groups'),
  createGroup: (payload: GroupPayload) => api.post<GroupRecord>('/admin/groups', payload),
  updateGroup: (id: string, payload: GroupPayload) =>
    api.put<GroupRecord>(`/admin/groups/${id}`, payload),
  deleteGroup: (id: string) => api.delete<{ message: string }>(`/admin/groups/${id}`),
  /** What a sign-in reporting these provider groups would resolve to. */

  audit: (page: number, pageSize: number, action?: string) =>
    api.get<Page<AuditEvent>>('/admin/audit', {
      page,
      page_size: pageSize,
      ...(action ? { action } : {}),
    }),
  verifyAudit: () =>
    api.get<{ message: string; details: { valid: boolean; checked: number } }>(
      '/admin/audit/verify',
    ),
};
