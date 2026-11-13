/** Assistant API: status, conversations, one turn. */

import { api } from '@/lib/api-client';
import type { AssistantStatus, ChatMessage, Conversation } from '@/lib/types';

export const assistantApi = {
  status: () => api.get<AssistantStatus>('/assistant'),
  conversations: () => api.get<Conversation[]>('/assistant/conversations'),
  open: (jobId?: string) =>
    api.post<Conversation>('/assistant/conversations', jobId ? { job_id: jobId } : {}),
  read: (id: string) => api.get<Conversation>(`/assistant/conversations/${id}`),
  remove: (id: string) => api.delete<{ message: string }>(`/assistant/conversations/${id}`),
  ask: (id: string, message: string) =>
    api.post<ChatMessage & { error?: string }>(`/assistant/conversations/${id}/ask`, { message }),
};

/**
 * Stream one answer, calling `onToken` as it arrives.
 *
 * `fetch` is used directly rather than the shared client: the client parses a
 * JSON body, and this response is an event stream read as it is produced. The
 * CSRF header and the credentials are the same ones the client sends.
 */
export async function streamAnswer(
  conversationId: string,
  message: string,
  onToken: (text: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`/api/v1/assistant/conversations/${conversationId}/stream`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    body: JSON.stringify({ message }),
    signal,
  });
  if (!response.ok || !response.body) {
    throw new Error(`The assistant answered HTTP ${response.status}.`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // Server-sent events are separated by a blank line.
    const blocks = buffer.split('\n\n');
    buffer = blocks.pop() ?? '';
    for (const block of blocks) {
      const event = /^event:\s*(.+)$/m.exec(block)?.[1]?.trim();
      const data = /^data:\s*(.+)$/m.exec(block)?.[1];
      if (!data) continue;
      if (event === 'token') {
        try {
          onToken(String(JSON.parse(data).text ?? ''));
        } catch {
          // A malformed frame is dropped rather than shown as content.
        }
      } else if (event === 'error') {
        throw new Error(String(JSON.parse(data).message ?? 'the assistant failed'));
      }
    }
  }
}
