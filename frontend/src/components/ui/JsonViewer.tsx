/** Collapsible viewer for raw provider payloads. */

import clsx from 'clsx';
import { ChevronDown, ChevronRight, Copy } from 'lucide-react';
import { useState } from 'react';

import { Button } from './index';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function Scalar({ value }: { value: unknown }) {
  if (value === null) return <span className="text-muted">null</span>;
  if (typeof value === 'boolean') return <span className="text-info">{String(value)}</span>;
  if (typeof value === 'number') return <span className="text-info">{value}</span>;
  return <span className="break-all text-content">{String(value)}</span>;
}

function Node({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  const branch = isRecord(value) || Array.isArray(value);

  if (!branch) {
    return (
      <div className="flex gap-2 py-0.5" style={{ paddingLeft: depth * 12 }}>
        <span className="shrink-0 text-muted">{name}:</span>
        <Scalar value={value} />
      </div>
    );
  }

  const entries = Array.isArray(value)
    ? value.map((item, index) => [String(index), item] as const)
    : Object.entries(value as Record<string, unknown>);

  return (
    <div style={{ paddingLeft: depth * 12 }}>
      <button
        type="button"
        onClick={() => setOpen((previous) => !previous)}
        className="flex items-center gap-1 py-0.5 text-left hover:text-primary"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-3 w-3" aria-hidden />
        ) : (
          <ChevronRight className="h-3 w-3" aria-hidden />
        )}
        <span className="text-muted">{name}</span>
        <span className="text-xs text-muted">
          {Array.isArray(value) ? `[${entries.length}]` : `{${entries.length}}`}
        </span>
      </button>
      {open
        ? entries.map(([key, item]) => (
            <Node key={key} name={key} value={item} depth={depth + 1} />
          ))
        : null}
    </div>
  );
}

export function JsonViewer({
  data,
  className,
}: {
  data: unknown;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  if (data === null || data === undefined) {
    return <p className="text-xs text-muted">No raw payload was stored for this analyzer.</p>;
  }

  return (
    <div className={clsx('rounded-lg border border-border bg-surface-sunken', className)}>
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-medium text-faint">Raw payload</span>
        <Button variant="ghost" onClick={copy} icon={<Copy className="h-3.5 w-3.5" />}>
          {copied ? 'Copied' : 'Copy JSON'}
        </Button>
      </div>
      <div className="max-h-96 overflow-auto p-3 font-mono text-xs">
        {isRecord(data) || Array.isArray(data) ? (
          Object.entries(isRecord(data) ? data : { items: data }).map(([key, value]) => (
            <Node key={key} name={key} value={value} depth={0} />
          ))
        ) : (
          <Scalar value={data} />
        )}
      </div>
    </div>
  );
}
