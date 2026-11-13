/**
 * Neutral demo data for the screenshot run.
 *
 * Nothing here belongs to anyone being investigated: the two IANA example
 * domains, the address example.com is documented at, and a public resolver.
 * None of them reveals a user or a case.
 *
 * Documentation ranges such as RFC 5737 would be the obvious choice, but they
 * are not routable and the SSRF guard refuses them, so the seed fails — which
 * is exactly what the guard should do.
 */

export const DEMO_OBSERVABLES = [
  { value: '93.184.216.34', playbook: 'Free sources only', tags: ['demo', 'triage'] },
  { value: 'example.com', playbook: 'Domain reconnaissance', tags: ['demo'] },
  { value: 'example.org', playbook: 'Domain reconnaissance', tags: ['demo', 'watchlist'] },
  { value: '1.1.1.1', playbook: 'Free sources only', tags: ['demo'] },
] as const;

export const DEMO_ADMIN = {
  username: process.env.XENOPROXY_DEMO_USER ?? 'admin',
  password: process.env.XENOPROXY_DEMO_PASSWORD ?? '',
} as const;
