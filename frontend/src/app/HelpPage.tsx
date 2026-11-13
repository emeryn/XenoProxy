/** Embedded help, bundled at build time from docs/help. */

import { PageHeader } from './AppShell';
import { Card } from '@/components/ui';

const SECTIONS: { title: string; body: string[] }[] = [
  {
    title: 'Submitting a scan',
    body: [
      'Paste an observable in New scan. XenoProxy classifies it as an IP address, domain, URL, hash or generic value while you type, and refangs defanged input such as 1.1.1[.]1 or hxxps://example[.]com.',
      'Only sources that support the detected type, are enabled and have their credentials configured are offered. Pick individual analyzers, or a playbook that groups them.',
      'Analyses run in the background and in parallel. The job page updates itself until every source has finished.',
    ],
  },
  {
    title: 'Cache and quotas',
    body: [
      'A successful result is reused for the same observable and source inside that source’s cache window, which spares the external API quota. Reused reports are marked "from cache".',
      'Tick "Force a refresh" to query every source again. Use it when you need fresh data, not by default.',
    ],
  },
  {
    title: 'Reading a job',
    body: [
      'The banner shows the aggregated verdict: the worst verdict any source reported. Open the per-source tabs for the normalised summary and the raw provider payload.',
      'A source that fails, times out or hits its quota is reported as Failed on its own tab. The rest of the job still completes, and the job status becomes Partial.',
      'Export the job as JSON for tooling, or as Markdown for an incident write-up.',
    ],
  },
  {
    title: 'For administrators',
    body: [
      'Admin, Plugins & keys is where API credentials are stored. A credential is sealed in the backend vault; afterwards only its last four characters are ever shown.',
      'A source cannot be enabled until its required credentials are present. Deleting a required credential disables the source.',
      'Timeouts, cache lifetime and per-source options are set on the same page. Every change is written to the audit trail.',
    ],
  },
  {
    title: 'Adding a source (administrators)',
    body: [
      'Admin, Plugins installs an analyzer without rebuilding the image: upload a zip holding a plugin.json manifest, or copy the folder into the plugins volume and press Rescan.',
      'The archive is checked before anything is written, and a plugin cannot take the name of a built-in analyzer. A plugin runs with the backend’s privileges, so read its code and only accept plugins from a source you trust; every installation is audited with the archive digest.',
      'The format and a working example are in docs/plugin-example in the repository.',
    ],
  },
  {
    title: 'Calling XenoProxy from a script or n8n',
    body: [
      'Create a personal token in My access and send it as an Authorization: Bearer header. The token carries your own permissions.',
      'POST /api/v1/jobs with an observable and either analyzers or a playbook, then poll GET /api/v1/jobs/{id} until the status is terminal.',
    ],
  },
];

export function HelpPage() {
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        breadcrumb={['Home', 'Help']}
        title="Help"
        description="How to use XenoProxy day to day."
      />
      <div className="space-y-3">
        {SECTIONS.map((section) => (
          <Card key={section.title} title={section.title}>
            {section.body.map((paragraph) => (
              <p key={paragraph.slice(0, 32)} className="mb-2 text-sm last:mb-0">
                {paragraph}
              </p>
            ))}
          </Card>
        ))}
      </div>
    </div>
  );
}
