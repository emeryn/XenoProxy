/** Job API. */

import { api, apiDownload } from '@/lib/api-client';
import type {
  JobDetail,
  JobStats,
  JobSummary,
  Page,
  PluginReportDetail,
} from '@/lib/types';

export interface JobFilters {
  page: number;
  page_size: number;
  search?: string;
  status?: string;
  verdict?: string;
  observable_type?: string;
  tag?: string;
  requested_by?: string;
  /** true shows only jobs a pivot created, false only submitted ones. */
  derived?: boolean;
}

export const jobsApi = {
  list: (filters: JobFilters) => api.get<Page<JobSummary>>('/jobs', { ...filters }),
  get: (jobId: string) => api.get<JobDetail>(`/jobs/${jobId}`),
  children: (jobId: string) => api.get<JobSummary[]>(`/jobs/${jobId}/children`),
  report: (jobId: string, pluginName: string) =>
    api.get<PluginReportDetail>(`/jobs/${jobId}/reports/${pluginName}`),
  updateTags: (jobId: string, tags: string[]) =>
    api.patch<JobDetail>(`/jobs/${jobId}/tags`, { tags }),
  rerun: (jobId: string) => api.post<JobDetail>(`/jobs/${jobId}/rerun`),
  /** Stop a running job at its next checkpoint. */
  kill: (jobId: string) => api.post<{ message: string }>(`/jobs/${jobId}/kill`),
  /** Re-run one failed, killed or skipped plugin instead of the whole job. */
  retryReport: (jobId: string, reportId: string) =>
    api.post<JobDetail>(`/jobs/${jobId}/reports/${reportId}/retry`),
  stats: () => api.get<JobStats>('/jobs/stats/overview'),
  download: (jobId: string, format: 'json' | 'markdown') =>
    apiDownload(
      `/jobs/${jobId}/export?format=${format}`,
      `xenoproxy-${jobId}.${format === 'json' ? 'json' : 'md'}`,
    ),
};
