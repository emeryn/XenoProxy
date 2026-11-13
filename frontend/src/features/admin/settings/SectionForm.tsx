/**
 * One settings section, rendered from the schema the backend publishes.
 *
 * The sections hold well over a hundred fields between them. Writing one form
 * per section by hand would mean one place per section to forget a bound, and a
 * field added to a model would silently never appear. Rendering from the schema
 * means the model stays the single declaration.
 *
 * A sealed field is recognised by its `<field>_set` companion: the value itself
 * is never sent to the browser, so the input starts empty, an empty submission
 * keeps what is stored, and clearing is an explicit action.
 *
 * Layout follows the shape of a field rather than listing everything in one
 * column: switches read as a block of policy, a certificate bundle or a prompt
 * needs the full width and a monospace face, and short values pair up.
 */

import { useMemo, useState } from 'react';

import { Badge, Button, Field, Input, Select, Textarea, Toggle } from '@/components/ui';
import type { SchemaProperty, SectionSchema, SectionValues } from '@/lib/types';

const SECRET_SUFFIX = '_set';

function titleOf(name: string, property: SchemaProperty): string {
  if (property.title) return property.title;
  return name.replace(/_/g, ' ').replace(/^./, (char) => char.toUpperCase());
}

/** A Pydantic `Literal` reaches the schema either as `enum` or inside `anyOf`. */
function choicesOf(property: SchemaProperty): string[] | null {
  if (property.enum) return property.enum;
  const nested = property.anyOf?.find((entry) => entry.enum)?.enum;
  return nested ?? null;
}

function typeOf(property: SchemaProperty): string {
  if (property.type) return property.type;
  const concrete = property.anyOf?.find((entry) => entry.type && entry.type !== 'null');
  return concrete?.type ?? 'string';
}

/** Fields that are pasted rather than typed, and need room and a fixed pitch. */
const MONOSPACE_FIELDS = new Set(['ca_bundle', 'system_prompt']);

function isMultiline(name: string, property: SchemaProperty): boolean {
  return MONOSPACE_FIELDS.has(name) || (property.maxLength ?? 0) > 4096;
}

function rowsFor(name: string): number {
  if (name === 'ca_bundle') return 12;
  if (name === 'system_prompt') return 14;
  return 6;
}

function placeholderFor(name: string): string {
  if (name === 'ca_bundle') {
    return '-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n\nPaste one or more certificates.';
  }
  if (name === 'system_prompt') return 'Leave empty to use the prompt shipped with the application.';
  return '';
}

/** A field spanning the whole form rather than sharing a row. */
function isWide(name: string, property: SchemaProperty): boolean {
  const kind = typeOf(property);
  return isMultiline(name, property) || kind === 'array' || kind === 'object';
}

export function SectionForm({
  name,
  schema,
  stored,
  managed,
  onSave,
  onTest,
  saving,
  testing,
  testTarget,
  hidden,
  children,
}: {
  name: string;
  schema: SectionSchema;
  stored: SectionValues;
  managed: string[];
  onSave: (values: SectionValues) => void;
  onTest?: (values: SectionValues, target: string) => void;
  saving: boolean;
  testing: boolean;
  /** Label and placeholder of the probe's target, when the probe needs one. */
  testTarget?: { label: string; placeholder: string; required?: boolean };
  /** Fields another control already owns, so the form does not offer them twice. */
  hidden?: readonly string[];
  children?: React.ReactNode;
}) {
  const [draft, setDraft] = useState<SectionValues>(() => ({ ...stored }));
  const [target, setTarget] = useState('');
  const [cleared, setCleared] = useState<Record<string, boolean>>({});

  const fields = useMemo(
    () =>
      Object.entries(schema.properties ?? {}).filter(
        // The `<field>_set` companions are state, not inputs, and a field a
        // connection profile owns is edited there instead of here.
        ([key]) => !key.endsWith(SECRET_SUFFIX) && !(hidden ?? []).includes(key),
      ),
    [schema, hidden],
  );

  const secretNames = useMemo(
    () =>
      new Set(
        Object.keys(stored)
          .filter((key) => key.endsWith(SECRET_SUFFIX))
          .map((key) => key.slice(0, -SECRET_SUFFIX.length)),
      ),
    [stored],
  );

  // Switches first and together: they are the policy of the section, and
  // scattering them between text inputs is what made it hard to read.
  const switches = fields.filter(
    ([key, property]) => typeOf(property) === 'boolean' && !secretNames.has(key),
  );
  const rest = fields.filter(
    ([key, property]) => typeOf(property) !== 'boolean' || secretNames.has(key),
  );

  function set(key: string, value: unknown) {
    setDraft((previous) => ({ ...previous, [key]: value }));
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const payload: SectionValues = {};
    for (const [key] of fields) {
      if (managed.includes(key)) continue;
      if (secretNames.has(key)) {
        // Empty keeps the stored value; clearing is said explicitly.
        if (cleared[key]) payload[`${key}_clear`] = true;
        else if (String(draft[key] ?? '')) payload[key] = draft[key];
        continue;
      }
      payload[key] = draft[key];
    }
    onSave(payload);
  }

  function renderInput(key: string, property: SchemaProperty) {
    const readOnly = managed.includes(key);
    const inputId = `${name}-${key}`;
    const choices = choicesOf(property);
    const kind = typeOf(property);
    const current = draft[key];

    if (secretNames.has(key)) {
      const isSet = Boolean(stored[`${key}${SECRET_SUFFIX}`]) && !cleared[key];
      return (
        <div className="space-y-2">
          <Input
            id={inputId}
            type="password"
            autoComplete="off"
            spellCheck={false}
            disabled={readOnly}
            placeholder={isSet ? 'Stored — enter a new value to replace it' : 'Not set'}
            value={String(current ?? '')}
            onChange={(event) => {
              set(key, event.target.value);
              setCleared((previous) => ({ ...previous, [key]: false }));
            }}
          />
          <div className="flex flex-wrap items-center gap-2">
            {isSet ? <Badge tone="success">Stored</Badge> : <Badge tone="neutral">Not set</Badge>}
            {cleared[key] ? <Badge tone="warning">Will be removed on save</Badge> : null}
            {isSet && !readOnly ? (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  set(key, '');
                  setCleared((previous) => ({ ...previous, [key]: true }));
                }}
              >
                Clear it
              </Button>
            ) : null}
          </div>
        </div>
      );
    }

    if (choices) {
      return (
        <Select
          id={inputId}
          disabled={readOnly}
          value={String(current ?? '')}
          onChange={(event) => set(key, event.target.value)}
        >
          {choices.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </Select>
      );
    }

    if (kind === 'array') {
      // A list of short strings reads best as one entry per line.
      const lines = Array.isArray(current) ? (current as string[]).join('\n') : '';
      return (
        <Textarea
          id={inputId}
          rows={4}
          disabled={readOnly}
          value={lines}
          placeholder="One entry per line"
          onChange={(event) =>
            set(
              key,
              event.target.value
                .split('\n')
                .map((entry) => entry.trim())
                .filter(Boolean),
            )
          }
        />
      );
    }

    if (kind === 'object') {
      return (
        <Textarea
          id={inputId}
          rows={5}
          disabled={readOnly}
          defaultValue={JSON.stringify(current ?? {}, null, 2)}
          placeholder="{}"
          onChange={(event) => {
            try {
              set(key, JSON.parse(event.target.value || '{}'));
            } catch {
              // Left as typed until it parses; the backend validates anyway.
            }
          }}
        />
      );
    }

    if (isMultiline(key, property)) {
      return (
        <Textarea
          id={inputId}
          rows={rowsFor(key)}
          disabled={readOnly}
          spellCheck={false}
          value={String(current ?? '')}
          placeholder={placeholderFor(key)}
          onChange={(event) => set(key, event.target.value)}
        />
      );
    }

    const numeric = kind === 'integer' || kind === 'number';
    return (
      <Input
        id={inputId}
        type={numeric ? 'number' : 'text'}
        disabled={readOnly}
        min={property.minimum}
        max={property.maximum}
        step={kind === 'number' ? 'any' : undefined}
        className={numeric ? 'max-w-40' : undefined}
        value={String(current ?? '')}
        onChange={(event) => set(key, numeric ? Number(event.target.value) : event.target.value)}
      />
    );
  }

  function managedNote(key: string) {
    if (!managed.includes(key)) return null;
    return (
      <p className="mt-1.5 flex items-center gap-1.5 text-xs text-muted">
        <Badge tone="info">Managed by the environment</Badge>
        Pinned by the deployment.
      </p>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-6">
      {children}

      {switches.length > 0 ? (
        <fieldset className="space-y-3.5 rounded-lg border border-border-subtle bg-surface-sunken p-4">
          <legend className="px-1 text-xs font-medium uppercase tracking-wide text-faint">
            Behaviour
          </legend>
          {switches.map(([key, property]) => (
            <div key={key}>
              <Toggle
                id={`${name}-${key}`}
                disabled={managed.includes(key)}
                checked={Boolean(draft[key])}
                onChange={(next) => set(key, next)}
                label={titleOf(key, property)}
                description={property.description}
              />
              {managedNote(key)}
            </div>
          ))}
        </fieldset>
      ) : null}

      <div className="grid gap-x-5 gap-y-1 sm:grid-cols-2">
        {rest.map(([key, property]) => (
          <Field
            key={key}
            className={isWide(key, property) ? 'sm:col-span-2' : undefined}
            label={titleOf(key, property)}
            htmlFor={`${name}-${key}`}
            hint={property.description}
          >
            {renderInput(key, property)}
            {managedNote(key)}
          </Field>
        ))}
      </div>

      {testTarget ? (
        <Field label={testTarget.label} htmlFor={`${name}-probe-target`} className="mb-0">
          <Input
            id={`${name}-probe-target`}
            value={target}
            placeholder={testTarget.placeholder}
            onChange={(event) => setTarget(event.target.value)}
          />
        </Field>
      ) : null}

      <div className="flex flex-wrap justify-end gap-2 border-t border-border-subtle pt-4">
        {onTest ? (
          <Button
            type="button"
            loading={testing}
            disabled={Boolean(testTarget?.required) && !target.trim()}
            onClick={() => onTest(draft, target.trim())}
          >
            Test connection
          </Button>
        ) : null}
        <Button type="submit" variant="primary" loading={saving}>
          Save this section
        </Button>
      </div>
    </form>
  );
}
