# Using XenoProxy

## Running a scan

1. Open **New scan** and paste the observable. XenoProxy classifies it as you type and
   refangs defanged input, so `1.1.1[.]1` and `hxxps://example[.]com` work as pasted.
2. Pick a **playbook** for a ready-made pipeline, or tick individual analyzers.
   Only sources that support the detected type, are enabled and have their
   credentials configured are offered; the rest are listed under "not available
   yet" with the reason.
3. Optionally open **After the analysis**. Nothing there runs unless you pick it:
   - a **connector** publishes the finished job to another platform, so the
     observable, its verdict and its tags leave XenoProxy;
   - a **pivot** analyses what it derives from this job — the domain behind a
     flagged URL, the addresses a bad domain resolves to — by creating a child
     job for each. It only acts on a suspicious or malicious verdict.

   A playbook may already include either; the card says so.
4. Add tags if the job belongs to an incident. They make it findable later.
5. Tick **Force a refresh** only when you need fresh data: it bypasses the cache
   and spends an API quota on every selected source.
6. Run the analysis. The job page updates itself until every plugin finishes.
   **Stop** halts a run you launched by mistake: nothing further starts, and the
   results already in are kept.

## Reading a result

The banner shows the aggregated verdict, which is the worst verdict any
**analyzer** reported, with the open ports, CVEs, geolocation and networks found
across all sources. Exports and pivots do not vote: "published successfully"
says nothing about whether the address is malicious.

The overview groups the reports by phase — Analyzers, then Exports, then Pivots
— in the order they ran. Each plugin also has its own tab with the normalised
summary and the raw provider payload underneath.

A plugin marked **Failed** did not answer: no credential, a timeout, or the
provider's quota. The rest of the job is unaffected and the job shows as
*Partial*. **Retry** re-runs that one plugin without touching the others or
spending their quota again. A source marked **cache** reused an earlier
identical lookup.

A plugin marked **Skipped** declined, and says why: an export whose verdict
floor was not met, or a pivot on a clean result.

### Following an investigation

When a pivot created child jobs, the Pivots tab lists what it derived and links
to each child, and a **Child jobs** card summarises them. A child job carries a
banner back to its parent and the name of the pivot that produced it, so you can
walk the investigation in either direction.

## Exporting

**JSON** contains everything, including raw payloads, and is meant for tooling.
**Markdown** is a readable incident write-up. Both are listed in the audit trail.

## Calling XenoProxy from a script or n8n

Create a token in **My access**, then send it as `Authorization: Bearer <token>`.
The token carries your own permissions, is shown once and can be revoked.

```
POST /api/v1/jobs      {"observable": "8.8.8.8", "playbook": "Fast IP triage"}
GET  /api/v1/jobs/{id} until "status" is SUCCESS, PARTIAL_FAILURE or FAILED
```

Send an `Idempotency-Key` header on POST so a retry cannot create a second job.

## Keyboard

`Ctrl+K` or `/` focuses the search, `Esc` closes a dialog, `Enter` submits a form.


## Analysing a file

On the scan page, **Analyse a file instead** takes a sample from your machine.
Its SHA-256 is computed in your browser and fills the observable field, so the
file is classified, matched against playbooks and offered the same hash sources
as a digest you typed — and you can see at once whether the team has looked at
this sample before.

### A sample in a password-protected archive

A sample normally arrives zipped with a password — `infected` by convention —
so that nothing opens it by accident on the way. Drop the archive in as it is.
XenoProxy opens it **only to hash what is inside**: nothing is extracted, and
the job is about the file inside, which is what you actually want looked up.
The archive is kept as context, with the hashes of everything it held.

The conventional passwords are tried automatically. An unusual one goes in the
password field beside the file, or in **Settings › Scanning** for a password
your team uses regularly.

An archive holding several files keeps its own digest as the observable, and
lists the inner hashes for you to pick from — guessing which one you meant
would be worse than saying so. An archive inside an archive is not opened.

### Whether the file itself leaves

By default **it does not**. Only the hashes are sent to providers, which
identify the sample without disclosing it. A sandbox that would submit the file
reports that it could not run, rather than quietly returning "nothing found"
from a detonation that never happened.

An administrator can allow it in **Settings › Scanning**. It is off by default
because a file under investigation may be confidential, and sending it to a
third party cannot be taken back.

The bytes are stored with the job so a sandbox can submit the sample where that
is allowed. They are never served back: there is no download, which is what
keeps a stored sample from becoming a way to hand malware to a browser.
