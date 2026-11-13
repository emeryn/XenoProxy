/**
 * Saved connections to an inference server.
 *
 * A profile answers *where the model is and how it answers*; the section below
 * it answers *what the assistant is allowed to do*. Keeping them apart is what
 * lets an operator keep a local Ollama and a hosted gateway side by side and
 * switch between them without touching a single policy field.
 *
 * The key and the header values are never sent back by the API, so the form
 * starts empty and an empty submission keeps what is stored. Header names are
 * returned in the clear, which is enough to show the shape of a profile.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, ListRestart, Pencil, Plug, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';

import {
  Badge,
  Button,
  EmptyState,
  Field,
  Input,
  Select,
  Skeleton,
  Textarea,
} from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import type { AssistantProfile, AssistantProfileWrite } from '@/lib/types';
import { settingsApi } from './api';

/**
 * The assistant fields a connection owns.
 *
 * They stay in the settings model so an instance with no profile keeps
 * working exactly as before, but the form stops offering them once profiles
 * exist: two places to set the same address is how they end up disagreeing.
 */
export const PROFILE_OWNED = [
  'provider',
  'base_url',
  'api_key',
  'headers',
  'model',
  'timeout',
  'temperature',
  'top_p',
  'max_tokens',
  'context_tokens',
] as const;

const BLANK: AssistantProfileWrite = {
  name: '',
  provider: 'openai',
  base_url: '',
  model: '',
  timeout: 120,
  temperature: 0.2,
  top_p: 0.95,
  max_tokens: 2048,
  context_tokens: 0,
  api_key: '',
};

/** Headers are edited as `Name: value` lines, which is how they are read. */
function parseHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const index = line.indexOf(':');
    if (index <= 0) continue;
    const name = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim();
    if (name) headers[name] = value;
  }
  return headers;
}

export function AssistantProfiles() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<string | 'new' | null>(null);
  const [draft, setDraft] = useState<AssistantProfileWrite>(BLANK);
  const [headerText, setHeaderText] = useState('');
  const [probe, setProbe] = useState<{ ok: boolean; detail: string } | null>(null);
  // What the server said it serves, so the model is chosen rather than typed.
  const [models, setModels] = useState<string[]>([]);

  const query = useQuery({
    queryKey: ['admin', 'assistant-profiles'],
    queryFn: settingsApi.listProfiles,
  });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'assistant-profiles'] });
    void queryClient.invalidateQueries({ queryKey: ['admin', 'settings'] });
  }

  function fail(title: string) {
    return (error: unknown) =>
      toast.error(title, error instanceof ApiError ? error.message : 'Unexpected failure.');
  }

  const saveMutation = useMutation({
    mutationFn: (payload: AssistantProfileWrite) =>
      editing && editing !== 'new'
        ? settingsApi.updateProfile(editing, payload)
        : settingsApi.createProfile(payload),
    onSuccess: (profile) => {
      toast.success(`${profile.name} saved`);
      setEditing(null);
      setProbe(null);
      invalidate();
    },
    onError: fail('The connection was refused'),
  });

  const activateMutation = useMutation({
    mutationFn: settingsApi.activateProfile,
    onSuccess: (profile) => {
      toast.success(`${profile.name} is now in use`);
      invalidate();
    },
    onError: fail('The connection could not be activated'),
  });

  const deleteMutation = useMutation({
    mutationFn: settingsApi.deleteProfile,
    onSuccess: (result) => {
      toast.success(result.message);
      invalidate();
    },
    onError: fail('The connection could not be deleted'),
  });

  const modelsMutation = useMutation({
    mutationFn: () =>
      settingsApi.listModels({
        provider: draft.provider,
        base_url: draft.base_url,
        timeout: draft.timeout,
        ...(draft.api_key ? { api_key: draft.api_key } : {}),
        ...(editing && editing !== 'new' ? { profile_id: editing } : {}),
        ...(Object.keys(parseHeaders(headerText)).length > 0
          ? { headers: parseHeaders(headerText) }
          : {}),
      }),
    onSuccess: (result) => {
      setModels(result.models);
      if (!result.ok) {
        toast.error('The models could not be listed', result.detail);
        return;
      }
      if (result.models.length === 0) {
        toast.error('The server offers no model.');
        return;
      }
      toast.success(result.detail);
      // Nothing chosen yet: start on the first rather than leaving it empty.
      if (!draft.model) setDraft((previous) => ({ ...previous, model: result.models[0] ?? '' }));
    },
    onError: fail('The models could not be listed'),
  });

  const testMutation = useMutation({
    mutationFn: settingsApi.testProfile,
    onSuccess: (result) => {
      setProbe({ ok: result.ok, detail: result.detail });
      if (result.ok && !result.model_present) {
        toast.error('The server answered, but it does not offer the configured model.');
      }
    },
    onError: fail('The connection could not be probed'),
  });

  function startEdit(profile: AssistantProfile) {
    setEditing(profile.id);
    setProbe(null);
    setModels([]);
    setDraft({
      name: profile.name,
      provider: profile.provider,
      base_url: profile.base_url,
      model: profile.model,
      timeout: profile.timeout,
      temperature: profile.temperature,
      top_p: profile.top_p,
      max_tokens: profile.max_tokens,
      context_tokens: profile.context_tokens,
      api_key: '',
    });
    // Values are not returned, so the names come back with an empty value for
    // the operator to fill only if they want to change them.
    setHeaderText(profile.header_names.map((name) => `${name}: `).join('\n'));
  }

  function startCreate() {
    setEditing('new');
    setProbe(null);
    setModels([]);
    setDraft(BLANK);
    setHeaderText('');
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const headers = parseHeaders(headerText);
    // A header left with an empty value is a name the operator did not retype:
    // sending it would blank a stored value they meant to keep.
    const filled = Object.fromEntries(Object.entries(headers).filter(([, value]) => value));
    saveMutation.mutate({
      ...draft,
      ...(Object.keys(filled).length > 0 ? { headers: filled } : {}),
    });
  }

  const profiles = query.data ?? [];

  return (
    <section className="mb-6 rounded-lg border border-border bg-surface-sunken p-4">
      <header className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Plug className="h-4 w-4 text-primary" aria-hidden />
            Connections
          </h3>
          <p className="mt-0.5 text-xs text-muted">
            Where the model lives. The settings below say what the assistant may do with it.
          </p>
        </div>
        <Button
          type="button"
          size="sm"
          onClick={startCreate}
          icon={<Plus className="h-3.5 w-3.5" aria-hidden />}
        >
          Add a connection
        </Button>
      </header>

      {query.isLoading ? (
        <Skeleton className="h-20 rounded-lg" />
      ) : profiles.length === 0 && editing === null ? (
        <EmptyState
          icon={<Plug className="h-5 w-5" aria-hidden />}
          title="No connection yet"
          description="Without one, the assistant falls back to the fields stored in this section."
          action={
            <Button type="button" onClick={startCreate}>
              Add a connection
            </Button>
          }
        />
      ) : (
        <ul className="space-y-2">
          {profiles.map((profile) => (
            <li
              key={profile.id}
              className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2.5"
            >
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{profile.name}</span>
                  {profile.is_active ? <Badge tone="success">In use</Badge> : null}
                  <Badge tone="neutral">{profile.provider}</Badge>
                  {profile.api_key_set ? <Badge tone="info">Key stored</Badge> : null}
                </span>
                <span className="mt-0.5 block truncate font-mono text-xs text-muted">
                  {profile.model || 'no model set'} · {profile.base_url || 'no address set'}
                </span>
              </span>
              {!profile.is_active ? (
                <Button
                  type="button"
                  size="sm"
                  variant="subtle"
                  loading={activateMutation.isPending}
                  onClick={() => activateMutation.mutate(profile.id)}
                  icon={<Check className="h-3.5 w-3.5" aria-hidden />}
                >
                  Use
                </Button>
              ) : null}
              <Button
                type="button"
                size="sm"
                loading={testMutation.isPending}
                onClick={() => testMutation.mutate(profile.id)}
              >
                Test
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                aria-label={`Edit ${profile.name}`}
                onClick={() => startEdit(profile)}
                icon={<Pencil className="h-3.5 w-3.5" aria-hidden />}
              />
              <Button
                type="button"
                size="sm"
                variant="ghost"
                aria-label={`Delete ${profile.name}`}
                loading={deleteMutation.isPending}
                onClick={() => {
                  if (window.confirm(`Delete the connection "${profile.name}"?`)) {
                    deleteMutation.mutate(profile.id);
                  }
                }}
                icon={<Trash2 className="h-3.5 w-3.5" aria-hidden />}
              />
            </li>
          ))}
        </ul>
      )}

      {probe ? (
        <p
          className={`mt-3 rounded-lg border p-3 text-sm ${
            probe.ok
              ? 'border-success-border bg-success-soft text-success'
              : 'border-danger-border bg-danger-soft text-danger'
          }`}
          role="status"
        >
          {probe.detail}
        </p>
      ) : null}

      {editing !== null ? (
        <form
          onSubmit={submit}
          className="mt-4 animate-fade-rise rounded-lg border border-primary-border bg-surface p-4"
        >
          <div className="grid gap-x-5 gap-y-1 sm:grid-cols-2">
            <Field label="Name" htmlFor="profile-name" required>
              <Input
                id="profile-name"
                required
                maxLength={128}
                value={draft.name}
                onChange={(event) => setDraft({ ...draft, name: event.target.value })}
              />
            </Field>
            <Field label="API shape" htmlFor="profile-provider">
              <Select
                id="profile-provider"
                value={draft.provider}
                onChange={(event) =>
                  setDraft({ ...draft, provider: event.target.value as 'ollama' | 'openai' })
                }
              >
                <option value="openai">OpenAI-compatible</option>
                <option value="ollama">Ollama</option>
              </Select>
            </Field>
            <Field
              label="Base URL"
              htmlFor="profile-url"
              className="sm:col-span-2"
              hint="Without the path: https://openrouter.ai/api, or http://ollama:11434"
            >
              <Input
                id="profile-url"
                value={draft.base_url}
                spellCheck={false}
                placeholder="https://openrouter.ai/api"
                onChange={(event) => setDraft({ ...draft, base_url: event.target.value })}
              />
            </Field>
            <Field
              label="Model"
              htmlFor="profile-model"
              className="sm:col-span-2"
              hint={
                models.length > 0
                  ? `${models.length} offered by the server.`
                  : 'Set the address and the key, then list what the server serves.'
              }
            >
              <div className="flex gap-2">
                {models.length > 0 ? (
                  <Select
                    id="profile-model"
                    value={draft.model}
                    onChange={(event) => setDraft({ ...draft, model: event.target.value })}
                  >
                    {/* A model configured before the listing may not be in it;
                        keeping it as an option means opening the form does not
                        silently change which model a connection uses. */}
                    {!models.includes(draft.model) && draft.model ? (
                      <option value={draft.model}>{draft.model} (not offered)</option>
                    ) : null}
                    {models.map((model) => (
                      <option key={model} value={model}>
                        {model}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <Input
                    id="profile-model"
                    value={draft.model}
                    spellCheck={false}
                    placeholder="baidu/ernie-5.5-flash-preview:free"
                    onChange={(event) => setDraft({ ...draft, model: event.target.value })}
                  />
                )}
                <Button
                  type="button"
                  loading={modelsMutation.isPending}
                  disabled={!draft.base_url.trim()}
                  onClick={() => modelsMutation.mutate()}
                  icon={<ListRestart className="h-3.5 w-3.5" aria-hidden />}
                >
                  {models.length > 0 ? 'Refresh' : 'List models'}
                </Button>
              </div>
            </Field>
            <Field
              label="API key"
              htmlFor="profile-key"
              className="sm:col-span-2"
              hint="Left empty, the stored key is kept. Most local servers need none."
            >
              <Input
                id="profile-key"
                type="password"
                autoComplete="off"
                value={draft.api_key}
                placeholder="sk-…"
                onChange={(event) => setDraft({ ...draft, api_key: event.target.value })}
              />
            </Field>
            <Field
              label="Extra headers"
              htmlFor="profile-headers"
              className="sm:col-span-2"
              hint="One per line, as Name: value. A line left without a value keeps the stored one."
            >
              <Textarea
                id="profile-headers"
                rows={3}
                spellCheck={false}
                value={headerText}
                placeholder={'HTTP-Referer: https://xenoproxy.example\nX-Title: XenoProxy'}
                onChange={(event) => setHeaderText(event.target.value)}
              />
            </Field>
            <Field label="Temperature" htmlFor="profile-temperature">
              <Input
                id="profile-temperature"
                type="number"
                step="0.05"
                min={0}
                max={2}
                className="max-w-40"
                value={draft.temperature}
                onChange={(event) =>
                  setDraft({ ...draft, temperature: Number(event.target.value) })
                }
              />
            </Field>
            <Field label="Top-p" htmlFor="profile-top-p">
              <Input
                id="profile-top-p"
                type="number"
                step="0.05"
                min={0}
                max={1}
                className="max-w-40"
                value={draft.top_p}
                onChange={(event) => setDraft({ ...draft, top_p: Number(event.target.value) })}
              />
            </Field>
            <Field label="Maximum tokens" htmlFor="profile-max-tokens">
              <Input
                id="profile-max-tokens"
                type="number"
                min={64}
                max={32768}
                className="max-w-40"
                value={draft.max_tokens}
                onChange={(event) => setDraft({ ...draft, max_tokens: Number(event.target.value) })}
              />
            </Field>
            <Field
              label="Context window"
              htmlFor="profile-context"
              hint="0 leaves it to the server."
            >
              <Input
                id="profile-context"
                type="number"
                min={0}
                className="max-w-40"
                value={draft.context_tokens}
                onChange={(event) =>
                  setDraft({ ...draft, context_tokens: Number(event.target.value) })
                }
              />
            </Field>
            <Field label="Timeout (seconds)" htmlFor="profile-timeout">
              <Input
                id="profile-timeout"
                type="number"
                min={5}
                max={900}
                className="max-w-40"
                value={draft.timeout}
                onChange={(event) => setDraft({ ...draft, timeout: Number(event.target.value) })}
              />
            </Field>
          </div>

          <div className="mt-3 flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setEditing(null)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={saveMutation.isPending}>
              {editing === 'new' ? 'Add it' : 'Save'}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}
