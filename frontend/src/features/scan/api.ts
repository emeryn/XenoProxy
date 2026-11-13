/** Scan submission API. */

import { api, apiUpload } from '@/lib/api-client';
import type {
  CurrentUser,
  JobDetail,
  JobSummary,
  Page,
  ObservablePreview,
  Playbook,
  Plugin,
  PluginType,
} from '@/lib/types';

export interface SubmitPayload {
  observable: string;
  analyzers: string[];
  /** Named explicitly or they do not run: an export leaves the instance. */
  connectors: string[];
  /** Named explicitly or they do not run: a pivot creates further jobs. */
  pivots: string[];
  playbook: string | null;
  tags: string[];
  force_rescan: boolean;
}

export const scanApi = {
  preview: (value: string) => api.post<ObservablePreview>('/jobs/preview', { value }),
  plugins: (pluginType?: PluginType) =>
    api.get<Plugin[]>('/plugins', pluginType ? { plugin_type: pluginType } : undefined),
  playbooks: () => api.get<Playbook[]>('/playbooks'),
  /** The team's latest jobs, for the scan page's empty state. */
  recent: (pageSize: number) =>
    api.get<Page<JobSummary>>('/jobs', { page: 1, page_size: pageSize }),
  submit: (payload: SubmitPayload) => api.post<JobDetail>('/jobs', payload),
  /** The sample's digest becomes the observable; the bytes stay with the job. */
  submitFile: (file: File, options: Omit<SubmitPayload, 'observable'>) => {
    const form = new FormData();
    form.append('file', file);
    form.append('options', JSON.stringify(options));
    return apiUpload<JobDetail>('/jobs/file', form);
  },
  savePreferences: (defaultPlaybook: string | null) =>
    api.put<CurrentUser>('/auth/me/preferences', { default_playbook: defaultPlaybook }),
};
