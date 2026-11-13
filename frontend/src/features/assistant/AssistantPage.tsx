/**
 * The assistant: conversations on the left, the exchange in the middle, and
 * what the conversation has looked at on the right.
 *
 * Two things here are security decisions rather than presentation ones.
 *
 * The answer is rendered as **plain text**, never as HTML or Markdown that
 * could carry a link or an image. A model repeats what it was given, and what
 * it was given includes provider reports that an attacker controls; an
 * auto-loaded remote image in an answer is a way to send the conversation
 * somewhere else, one pixel at a time.
 *
 * The agent's steps are shown in full. An analyst has to be able to see which
 * tool ran with which arguments before trusting a conclusion drawn from it.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Bot,
  ChevronDown,
  Loader2,
  MessageSquare,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Search,
  Send,
  Trash2,
  User,
  Wrench,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Menu,
  MenuItem,
  Skeleton,
} from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { VerdictBadge } from '@/components/ui/verdict';
import { ApiError } from '@/lib/api-client';
import { formatRelative } from '@/lib/format';
import type { AgentStep, ChatMessage, TouchedObservable, Verdict } from '@/lib/types';
import { assistantApi, streamAnswer } from './api';

const VERDICTS = new Set(['clean', 'suspicious', 'malicious', 'unknown']);

// A job in any other state is still moving, so the panel keeps watching it.
const TERMINAL_STATUSES = new Set(['SUCCESS', 'PARTIAL_FAILURE', 'FAILED', 'KILLED']);

const RAIL_STATE_KEY = 'xenoproxy.assistant.rail';

/**
 * The conversation rail starts hidden.
 *
 * A chat is read far more often than it is switched, and the rail costs the
 * message column a quarter of its width to list something an analyst picks
 * once. Hidden by default, with the picker in the header for the times they do
 * switch, and the choice is remembered.
 */
function readRailOpen(): boolean {
  try {
    return window.localStorage.getItem(RAIL_STATE_KEY) === 'open';
  } catch {
    return false;
  }
}

function StepTrace({ steps }: { steps: AgentStep[] }) {
  if (steps.length === 0) return null;
  return (
    <details className="mt-2.5 rounded-lg border border-border-subtle bg-surface-sunken px-2.5 py-1.5">
      <summary className="cursor-pointer text-xs text-muted marker:text-faint">
        <Wrench className="mr-1 inline h-3 w-3" aria-hidden />
        {steps.length} tool call{steps.length === 1 ? '' : 's'}
      </summary>
      <ol className="mt-2 space-y-2">
        {steps.map((step, index) => (
          <li key={`${step.tool}-${index}`} className="text-xs">
            <span className="flex flex-wrap items-center gap-2">
              <code className="rounded bg-surface px-1.5 py-0.5 font-mono">{step.tool}</code>
              {step.ok ? <Badge tone="success">ok</Badge> : <Badge tone="danger">refused</Badge>}
            </span>
            <pre className="mt-1 max-h-56 overflow-auto rounded-md bg-surface p-2 font-mono text-[11px] leading-relaxed">
              {JSON.stringify({ arguments: step.arguments, result: step.result }, null, 2)}
            </pre>
          </li>
        ))}
      </ol>
    </details>
  );
}

/** An avatar beside the bubble, so a long thread stays readable by shape. */
function Speaker({ mine }: { mine: boolean }) {
  return (
    <span
      className={`grid h-7 w-7 shrink-0 place-items-center rounded-pill ${
        mine
          ? 'bg-surface-raised text-muted'
          : 'bg-gradient-to-br from-accent-from to-accent-to text-primary-content'
      }`}
      aria-hidden
    >
      {mine ? <User className="h-3.5 w-3.5" /> : <Bot className="h-3.5 w-3.5" />}
    </span>
  );
}

function Bubble({ message }: { message: ChatMessage }) {
  const mine = message.role === 'user';
  return (
    <li className={`flex items-start gap-2.5 ${mine ? 'flex-row-reverse' : ''}`}>
      <Speaker mine={mine} />
      <div className={`min-w-0 max-w-[82%] ${mine ? 'text-right' : ''}`}>
        <p className="mb-1 text-[11px] text-faint">
          {mine ? 'You' : 'Assistant'} · {formatRelative(message.created_at)}
        </p>
        <div
          className={`inline-block rounded-lg border px-3.5 py-2.5 text-left ${
            mine
              ? 'border-primary-border bg-primary-soft'
              : 'border-border bg-surface-raised shadow-sm'
          }`}
        >
          {/* Plain text on purpose: see the note at the top of this file. */}
          <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
            {message.content}
          </p>
          <StepTrace steps={message.steps ?? []} />
        </div>
      </div>
    </li>
  );
}

/**
 * What the conversation has looked at.
 *
 * Twenty exchanges in, nobody remembers which addresses were checked or which
 * came back bad. The list is derived from the tool results the trace already
 * shows, so it can never claim something the conversation did not actually do.
 */
function TouchedPanel({ observables }: { observables: TouchedObservable[] }) {
  if (observables.length === 0) {
    return (
      <p className="px-1 text-xs text-faint">
        Nothing yet. Ask about an observable and it appears here.
      </p>
    );
  }
  return (
    <ul className="space-y-1.5">
      {observables.map((entry) => {
        const body = (
          <>
            <span className="block truncate font-mono text-xs group-hover:text-primary">
              {entry.value}
            </span>
            <span className="mt-1 flex flex-wrap items-center gap-1.5">
              {entry.type ? <Badge tone="info">{entry.type}</Badge> : null}
              {/* A scan the chat submitted is still running for a while after
                  the answer was written, so the state is shown rather than a
                  verdict that does not exist yet. */}
              {entry.status && !TERMINAL_STATUSES.has(entry.status) ? (
                <Badge tone="primary">
                  <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
                  {entry.status === 'PENDING' ? 'Queued' : 'Running'}
                </Badge>
              ) : entry.verdict && VERDICTS.has(entry.verdict) ? (
                <VerdictBadge verdict={entry.verdict as Verdict} />
              ) : null}
            </span>
          </>
        );
        return (
          <li key={entry.value}>
            {entry.job_id ? (
              <Link
                to={`/jobs/${entry.job_id}`}
                className="group block rounded-lg border border-border bg-surface-raised px-2.5 py-2 transition-colors duration-fast ease-out hover:border-border-strong"
              >
                {body}
              </Link>
            ) : (
              <div className="rounded-lg border border-border-subtle px-2.5 py-2">{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

export function AssistantPage() {
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [draft, setDraft] = useState('');
  const [streamed, setStreamed] = useState('');
  const [railOpen, setRailOpen] = useState(readRailOpen);
  const bottom = useRef<HTMLDivElement>(null);

  const conversationId = params.get('c') ?? '';
  const jobId = params.get('job') ?? '';

  const statusQuery = useQuery({ queryKey: ['assistant'], queryFn: assistantApi.status });
  const listQuery = useQuery({
    queryKey: ['assistant', 'conversations'],
    queryFn: assistantApi.conversations,
    enabled: Boolean(statusQuery.data?.available),
  });
  const threadQuery = useQuery({
    queryKey: ['assistant', 'conversation', conversationId],
    queryFn: () => assistantApi.read(conversationId),
    enabled: Boolean(conversationId),
    // A scan the assistant submitted finishes in the worker, minutes after the
    // answer was written. Without this the panel keeps showing the state the
    // tool saw, which is "pending" forever. Polling stops on its own once
    // every referenced job has reached a terminal state.
    refetchInterval: (query) =>
      (query.state.data?.observables ?? []).some(
        (entry) => entry.status && !TERMINAL_STATUSES.has(entry.status),
      )
        ? 4000
        : false,
  });

  function select(id: string) {
    const next = new URLSearchParams(params);
    next.set('c', id);
    next.delete('job');
    setParams(next, { replace: true });
  }

  const openMutation = useMutation({
    mutationFn: () => assistantApi.open(jobId || undefined),
    onSuccess: (conversation) => {
      void queryClient.invalidateQueries({ queryKey: ['assistant', 'conversations'] });
      select(conversation.id);
    },
    onError: (error) =>
      toast.error(
        'The conversation could not be opened',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      ),
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => assistantApi.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['assistant', 'conversations'] });
      const next = new URLSearchParams(params);
      next.delete('c');
      setParams(next, { replace: true });
    },
  });

  const askMutation = useMutation({
    mutationFn: async (message: string) => {
      const agent = statusQuery.data?.agent_enabled;
      if (agent) {
        // Agent mode does not stream: its steps have to finish before there is
        // an answer, and a half-answer a later step contradicts is worse.
        const answer = await assistantApi.ask(conversationId, message);
        if (answer.error) throw new Error(answer.error);
        return;
      }
      setStreamed('');
      await streamAnswer(conversationId, message, (token) =>
        setStreamed((previous) => previous + token),
      );
    },
    onSuccess: () => {
      setStreamed('');
      void queryClient.invalidateQueries({
        queryKey: ['assistant', 'conversation', conversationId],
      });
      void queryClient.invalidateQueries({ queryKey: ['assistant', 'conversations'] });
    },
    onError: (error) => {
      setStreamed('');
      // The question is stored even when the answer failed, so the thread is
      // reloaded here too: otherwise what the analyst typed would only appear
      // after a manual refresh, which reads as the message having been lost.
      void queryClient.invalidateQueries({
        queryKey: ['assistant', 'conversation', conversationId],
      });
      void queryClient.invalidateQueries({ queryKey: ['assistant', 'conversations'] });
      toast.error(
        'The assistant could not answer',
        error instanceof Error ? error.message : 'Unexpected failure.',
      );
    },
  });

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: 'smooth' });
  }, [threadQuery.data?.messages?.length, streamed]);

  useEffect(() => {
    try {
      window.localStorage.setItem(RAIL_STATE_KEY, railOpen ? 'open' : 'closed');
    } catch {
      // The preference is a convenience; a failed write is not an error.
    }
  }, [railOpen]);

  // Opening the page from a job starts a conversation anchored to it.
  useEffect(() => {
    if (jobId && !conversationId && statusQuery.data?.available && !openMutation.isPending) {
      openMutation.mutate();
    }
  }, [jobId, conversationId, statusQuery.data?.available]);

  if (statusQuery.isLoading) return <Skeleton className="h-64 rounded-lg" />;

  const status = statusQuery.data;
  if (!status?.available) {
    return (
      <div className="mx-auto max-w-3xl">
        <PageHeader breadcrumb={['Home', 'Assistant']} title="Assistant" />
        <Card>
          <p className="text-sm">
            {status?.reason || 'The assistant is not available on this instance.'}
          </p>
          {!status?.configured ? (
            <p className="mt-2 text-xs text-muted">
              An administrator configures the inference server in Admin, Settings, Assistant.
            </p>
          ) : null}
        </Card>
      </div>
    );
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const message = draft.trim();
    if (!message || !conversationId) return;
    setDraft('');
    askMutation.mutate(message);
  }

  const conversations = listQuery.data ?? [];
  const messages = threadQuery.data?.messages ?? [];
  const observables = threadQuery.data?.observables ?? [];

  return (
    <div>
      <PageHeader
        breadcrumb={['Home', 'Assistant']}
        title="Assistant"
        description={`${status.model} on ${status.provider}. Answers are grounded in the jobs you may see.`}
        actions={
          <>
            {status.agent_enabled ? (
              <Badge tone="warning" title={`Up to ${status.max_steps} tool calls per answer`}>
                Agent mode
              </Badge>
            ) : null}
            {status.allow_writes ? <Badge tone="danger">Writes allowed</Badge> : null}
            <Button
              variant="primary"
              loading={openMutation.isPending}
              onClick={() => openMutation.mutate()}
              icon={<Plus className="h-4 w-4" aria-hidden />}
            >
              New conversation
            </Button>
          </>
        }
      />

      {/* The three rails fill the window rather than the document: a chat that
          scrolls the whole page loses its composer off the bottom. */}
      <div
        className="grid h-[calc(100vh-var(--topbar-height)-11rem)] min-h-[32rem] gap-4"
        style={{
          gridTemplateColumns: railOpen
            ? 'var(--assistant-rail) minmax(0, 1fr) var(--assistant-aside)'
            : 'minmax(0, 1fr) var(--assistant-aside)',
        }}
      >
        <nav
          aria-label="Conversations"
          className={`min-h-0 flex-col ${railOpen ? 'hidden lg:flex' : 'hidden'}`}
        >
          <p className="mb-2 px-1 text-[11px] font-semibold uppercase tracking-wide text-faint">
            Conversations
          </p>
          {listQuery.isLoading ? (
            <Skeleton className="h-40 rounded-lg" />
          ) : conversations.length === 0 ? (
            <p className="px-1 text-xs text-faint">None yet — start one to ask about a job.</p>
          ) : (
            <ul className="min-h-0 flex-1 space-y-0.5 overflow-y-auto pr-1">
              {conversations.map((conversation) => {
                const active = conversation.id === conversationId;
                return (
                  <li key={conversation.id} className="group flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => select(conversation.id)}
                      aria-current={active ? 'true' : undefined}
                      className={`min-w-0 flex-1 rounded-lg px-2.5 py-2 text-left transition-colors duration-fast ease-out focus-visible:shadow-focus focus-visible:outline-none ${
                        active
                          ? 'bg-primary-soft text-primary'
                          : 'text-muted hover:bg-surface-hover hover:text-content'
                      }`}
                    >
                      <span className="block truncate text-sm">{conversation.title}</span>
                      <span className="block text-[11px] text-faint">
                        {formatRelative(conversation.updated_at)}
                      </span>
                    </button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="opacity-0 transition-opacity group-hover:opacity-100"
                      aria-label={`Delete the conversation ${conversation.title}`}
                      onClick={() => {
                        if (window.confirm(`Delete "${conversation.title}"?`)) {
                          removeMutation.mutate(conversation.id);
                        }
                      }}
                      icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </nav>

        <section className="card flex min-h-0 flex-col overflow-hidden">
          {/* The chat's own bar: it holds the rail toggle, and the picker that
              replaces the rail while it is hidden. */}
          <header className="flex items-center gap-2 border-b border-border-subtle px-3 py-2">
            <Button
              variant="ghost"
              size="sm"
              aria-label={railOpen ? 'Hide the conversation list' : 'Show the conversation list'}
              aria-expanded={railOpen}
              onClick={() => setRailOpen((open) => !open)}
              icon={
                railOpen ? (
                  <PanelLeftClose className="h-4 w-4" aria-hidden />
                ) : (
                  <PanelLeftOpen className="h-4 w-4" aria-hidden />
                )
              }
            />
            {railOpen ? (
              <span className="min-w-0 truncate text-sm font-medium">
                {conversations.find((entry) => entry.id === conversationId)?.title ??
                  'No conversation'}
              </span>
            ) : (
              <Menu
                align="start"
                trigger={({ open, toggle }) => (
                  <button
                    type="button"
                    onClick={toggle}
                    aria-haspopup="menu"
                    aria-expanded={open}
                    className="flex min-w-0 items-center gap-1.5 rounded-md px-2 py-1 text-sm font-medium transition-colors duration-fast ease-out hover:bg-surface-hover focus-visible:shadow-focus focus-visible:outline-none"
                  >
                    <MessageSquare className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden />
                    <span className="max-w-72 truncate">
                      {conversations.find((entry) => entry.id === conversationId)?.title ??
                        'Pick a conversation'}
                    </span>
                    <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden />
                  </button>
                )}
              >
                {({ close }) =>
                  conversations.length === 0 ? (
                    <p className="px-2.5 py-2 text-xs text-muted">No conversation yet.</p>
                  ) : (
                    <div className="max-h-80 overflow-y-auto">
                      {conversations.map((conversation) => (
                        <MenuItem
                          key={conversation.id}
                          onClick={() => {
                            close();
                            select(conversation.id);
                          }}
                        >
                          <span className="min-w-0">
                            <span className="block truncate">{conversation.title}</span>
                            <span className="block text-[11px] text-faint">
                              {formatRelative(conversation.updated_at)}
                            </span>
                          </span>
                        </MenuItem>
                      ))}
                    </div>
                  )
                }
              </Menu>
            )}
            {conversationId ? (
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto"
                aria-label="Delete this conversation"
                onClick={() => {
                  const title =
                    conversations.find((entry) => entry.id === conversationId)?.title ?? '';
                  if (window.confirm(`Delete "${title}"?`)) removeMutation.mutate(conversationId);
                }}
                icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />}
              />
            ) : null}
          </header>

          {!conversationId ? (
            <EmptyState
              icon={<MessageSquare className="h-5 w-5" aria-hidden />}
              title="Pick a conversation"
              description="Or start a new one. The assistant answers about the jobs you may see."
              action={
                <Button variant="primary" onClick={() => openMutation.mutate()}>
                  New conversation
                </Button>
              }
            />
          ) : threadQuery.error ? (
            <div className="p-4">
              <ErrorBanner
                message={
                  threadQuery.error instanceof ApiError
                    ? threadQuery.error.message
                    : 'The conversation could not be loaded.'
                }
                onRetry={() => void threadQuery.refetch()}
              />
            </div>
          ) : (
            <>
              <ul className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
                {messages.length === 0 && !streamed ? (
                  <li className="pt-8 text-center text-sm text-faint">
                    Ask about a job, an observable, or what this instance can run.
                  </li>
                ) : null}
                {messages.map((message) => (
                  <Bubble key={message.id} message={message} />
                ))}
                {streamed ? (
                  <li className="flex items-start gap-2.5">
                    <Speaker mine={false} />
                    <div className="max-w-[82%] rounded-lg border border-border bg-surface-raised px-3.5 py-2.5 shadow-sm">
                      <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
                        {streamed}
                      </p>
                    </div>
                  </li>
                ) : null}
                {askMutation.isPending && !streamed ? (
                  <li className="flex items-center gap-2.5">
                    <Speaker mine={false} />
                    <span className="flex gap-1" aria-label="The assistant is thinking">
                      {[0, 150, 300].map((delay) => (
                        <span
                          key={delay}
                          className="h-1.5 w-1.5 animate-bounce rounded-pill bg-muted"
                          style={{ animationDelay: `${delay}ms` }}
                        />
                      ))}
                    </span>
                  </li>
                ) : null}
                <div ref={bottom} />
              </ul>

              <form
                onSubmit={submit}
                className="flex items-end gap-2 border-t border-border-subtle p-3"
              >
                <label className="sr-only" htmlFor="assistant-input">
                  Your message
                </label>
                <textarea
                  id="assistant-input"
                  rows={1}
                  value={draft}
                  placeholder="Ask about a job, an observable, or what this instance can run"
                  maxLength={8000}
                  disabled={askMutation.isPending}
                  onChange={(event) => setDraft(event.target.value)}
                  onKeyDown={(event) => {
                    // Enter sends, Shift+Enter breaks the line: the message is
                    // usually one sentence, so sending is the common case.
                    if (event.key === 'Enter' && !event.shiftKey) {
                      event.preventDefault();
                      submit(event);
                    }
                  }}
                  className="max-h-40 min-h-10 flex-1 resize-none rounded-lg border border-border bg-surface-sunken px-3 py-2 text-sm transition-[border-color,box-shadow] duration-fast ease-out placeholder:text-faint hover:border-border-strong focus:border-primary focus:shadow-accent focus:outline-none disabled:opacity-55"
                />
                <Button
                  type="submit"
                  variant="primary"
                  loading={askMutation.isPending}
                  disabled={!draft.trim()}
                  icon={<Send className="h-4 w-4" aria-hidden />}
                  aria-label="Send"
                />
              </form>
            </>
          )}
        </section>

        <aside className="hidden min-h-0 flex-col lg:flex" aria-label="Observables in this conversation">
          <p className="mb-2 flex items-center gap-1.5 px-1 text-[11px] font-semibold uppercase tracking-wide text-faint">
            <Search className="h-3 w-3" aria-hidden />
            Looked at
          </p>
          <div className="min-h-0 flex-1 overflow-y-auto pr-1">
            {conversationId ? (
              <TouchedPanel observables={observables} />
            ) : (
              <p className="px-1 text-xs text-faint">Open a conversation to see what it covered.</p>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}
