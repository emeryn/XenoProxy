/**
 * Captures the README screenshots from the running application.
 *
 * It signs in, seeds a few fictitious jobs through the API, waits for them to
 * finish, then photographs the three views an operator sees first.
 */

import { expect, test, type Page } from '@playwright/test';

import { DEMO_ADMIN, DEMO_OBSERVABLES } from './fixtures/demo-data';

const SHOTS = '../docs/screenshots';

test.describe.configure({ mode: 'serial' });

async function signIn(page: Page): Promise<void> {
  await page.goto('/');
  await page.locator('#username').fill(DEMO_ADMIN.username);
  await page.locator('#password').fill(DEMO_ADMIN.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: /What are we looking at/ })).toBeVisible();
}

async function seed(page: Page): Promise<void> {
  for (const [index, observable] of DEMO_OBSERVABLES.entries()) {
    const response = await page.request.post('/api/v1/jobs', {
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Idempotency-Key': `demo-seed-${index}-0000-4000-8000-000000000000`,
      },
      data: {
        observable: observable.value,
        analyzers: [],
        connectors: [],
        pivots: [],
        playbook: observable.playbook,
        tags: [...observable.tags],
        force_rescan: false,
      },
    });
    // A silent failure here used to leave the captures showing whatever was
    // already in the database, so the seed must be loud.
    expect(response.ok(), await response.text()).toBeTruthy();
  }
}

test('capture the README screenshots', async ({ page }) => {
  test.skip(!DEMO_ADMIN.password, 'Set XENOPROXY_DEMO_PASSWORD to capture screenshots.');

  await signIn(page);
  await seed(page);

  // New scan, filled in, with the detected type and the compatible sources.
  await page.goto('/scan');
  await page.locator('#observable').fill('93.184.216[.]34');
  await expect(page.getByText('Refanged')).toBeVisible();
  await page.getByRole('radio', { name: /Free sources only/ }).click();
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${SHOTS}/new-scan.png`, fullPage: false });

  // Team history.
  await page.goto('/jobs');
  await expect(page.getByRole('heading', { name: 'Jobs' })).toBeVisible();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: `${SHOTS}/jobs-list.png`, fullPage: false });

  // A finished job, with its aggregated verdict and per-source tabs.
  await page.locator('tbody tr').first().click();
  await expect(page.getByRole('tab', { name: 'Overview' })).toBeVisible();
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `${SHOTS}/job-detail.png`, fullPage: false });

  // Administration: credentials and plugin activation.
  await page.goto('/admin/plugins');
  await expect(page.getByRole('heading', { name: 'Plugins and API keys' })).toBeVisible();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${SHOTS}/admin-analyzers.png`, fullPage: false });

  // Administration: installed plugin packages.
  await page.goto('/admin/plugin-packages');
  await expect(page.getByRole('heading', { name: 'Plugin packages' })).toBeVisible();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${SHOTS}/admin-plugins.png`, fullPage: false });
});
