/**
 * The scalar switches and thresholds of one group.
 *
 * These are declared one by one on the backend with their bounds, so the input
 * renders from the declaration and the bounds are shown rather than discovered
 * by being refused.
 */

import { useState } from 'react';

import { Badge, Button, Field, Input, Select } from '@/components/ui';
import type { SettingSpec } from '@/lib/types';

export function ScalarSection({
  specs,
  onSave,
  saving,
}: {
  specs: SettingSpec[];
  onSave: (values: Record<string, unknown>) => void;
  saving: boolean;
}) {
  const [draft, setDraft] = useState<Record<string, unknown>>({});

  function valueOf(spec: SettingSpec): unknown {
    return spec.key in draft ? draft[spec.key] : spec.value;
  }

  function set(key: string, value: unknown) {
    setDraft((previous) => ({ ...previous, [key]: value }));
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    // Only what actually changed is sent: the endpoint audits every key it is
    // given, and a no-op change in the trail is noise.
    const changed = Object.fromEntries(
      Object.entries(draft).filter(([key, value]) => {
        const spec = specs.find((entry) => entry.key === key);
        return spec && value !== spec.value;
      }),
    );
    onSave(changed);
    setDraft({});
  }

  if (specs.length === 0) {
    return <p className="text-sm text-muted">Nothing is configurable in this group.</p>;
  }

  return (
    <form onSubmit={submit}>
      <div className="grid gap-4">
        {specs.map((spec) => {
          const current = valueOf(spec);
          const inputId = `setting-${spec.key}`;
          const bounds =
            spec.type === 'integer' && spec.minimum !== null && spec.maximum !== null
              ? ` (${spec.minimum}–${spec.maximum})`
              : '';

          return (
            <Field
              key={spec.key}
              label={spec.label}
              htmlFor={inputId}
              hint={spec.help_text + bounds}
            >
              {spec.type === 'boolean' ? (
                <label className="flex items-center gap-2 text-sm">
                  <input
                    id={inputId}
                    type="checkbox"
                    className="h-4 w-4"
                    disabled={spec.managed_by_environment}
                    checked={Boolean(current)}
                    onChange={(event) => set(spec.key, event.target.checked)}
                  />
                  {current ? 'On' : 'Off'}
                </label>
              ) : spec.type === 'choice' ? (
                <Select
                  id={inputId}
                  disabled={spec.managed_by_environment}
                  value={String(current ?? '')}
                  onChange={(event) => set(spec.key, event.target.value)}
                >
                  {spec.choices.map((choice) => (
                    <option key={choice} value={choice}>
                      {choice}
                    </option>
                  ))}
                </Select>
              ) : (
                <Input
                  id={inputId}
                  type={spec.type === 'integer' ? 'number' : 'text'}
                  disabled={spec.managed_by_environment}
                  min={spec.minimum ?? undefined}
                  max={spec.maximum ?? undefined}
                  value={String(current ?? '')}
                  onChange={(event) =>
                    set(
                      spec.key,
                      spec.type === 'integer' ? Number(event.target.value) : event.target.value,
                    )
                  }
                />
              )}

              {spec.managed_by_environment ? (
                <p className="mt-1 text-xs text-muted">
                  <Badge tone="info">Managed by the environment</Badge> Pinned by{' '}
                  <code>{spec.environment_variable}</code>.
                </p>
              ) : null}
            </Field>
          );
        })}
      </div>

      <div className="mt-6 flex justify-end">
        <Button
          type="submit"
          variant="primary"
          loading={saving}
          disabled={Object.keys(draft).length === 0}
        >
          Save
        </Button>
      </div>
    </form>
  );
}
