/** Instance settings API: scalar switches, structured sections, transfer. */

import { api } from '@/lib/api-client';
import type {
  AssistantProfile,
  AssistantProfileWrite,
  ProbeResult,
  SectionValues,
  SettingsDocument,
} from '@/lib/types';

export const settingsApi = {
  read: () => api.get<SettingsDocument>('/admin/settings'),

  /** Scalar switches are changed in a batch, each against its declaration. */
  patchScalars: (values: Record<string, unknown>) =>
    api.patch<{ settings: SettingsDocument['settings']; applied: string[] }>('/admin/settings', {
      values,
    }),

  /** A section is saved whole: its fields only make sense together. */
  saveSection: (name: string, values: SectionValues) =>
    api.put<SectionValues>(`/admin/settings/sections/${name}`, { values }),

  /** Probe values that are not saved yet, so a bad one is never committed. */
  testSection: (name: string, values?: SectionValues, target?: string) =>
    api.post<ProbeResult>(`/admin/settings/sections/${name}/test`, {
      ...(values ? { values } : {}),
      ...(target ? { target } : {}),
    }),

  /** Saved connections to an inference server; one is active. */
  listProfiles: () => api.get<AssistantProfile[]>('/admin/settings/assistant/profiles'),
  createProfile: (payload: AssistantProfileWrite) =>
    api.post<AssistantProfile>('/admin/settings/assistant/profiles', payload),
  updateProfile: (id: string, payload: AssistantProfileWrite) =>
    api.put<AssistantProfile>(`/admin/settings/assistant/profiles/${id}`, payload),
  activateProfile: (id: string) =>
    api.post<AssistantProfile>(`/admin/settings/assistant/profiles/${id}/activate`),
  deleteProfile: (id: string) =>
    api.delete<{ message: string }>(`/admin/settings/assistant/profiles/${id}`),
  testProfile: (id: string) =>
    api.post<{ ok: boolean; detail: string; models: string[]; model_present: boolean }>(
      `/admin/settings/assistant/profiles/${id}/test`,
    ),

  /** What the server actually serves, for values being typed. */
  listModels: (payload: {
    provider: 'ollama' | 'openai';
    base_url: string;
    timeout?: number;
    api_key?: string;
    headers?: Record<string, string>;
    profile_id?: string;
  }) =>
    api.post<{ ok: boolean; detail: string; models: string[] }>(
      '/admin/settings/assistant/models',
      payload,
    ),

  exportConfiguration: () => api.get<Record<string, unknown>>('/admin/settings/export'),
  importConfiguration: (document: Record<string, unknown>) =>
    api.post<{ sections: string[]; settings: string[] }>('/admin/settings/import', {
      values: document,
    }),
};
