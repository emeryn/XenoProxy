import { expect, test } from '@playwright/test';

import { DEMO_ADMIN } from './fixtures/demo-data';

test('the search sits in the middle of the bar', async ({ page }) => {
  await page.goto('/');
  await page.locator('#username').fill(DEMO_ADMIN.username);
  await page.locator('#password').fill(DEMO_ADMIN.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: /What are we looking at/ })).toBeVisible();
  await page.waitForTimeout(600);

  const box = await page.locator('#global-search').boundingBox();
  const width = page.viewportSize()?.width ?? 0;
  const centre = (box?.x ?? 0) + (box?.width ?? 0) / 2;
  console.log(`viewport centre ${width / 2}, search centre ${Math.round(centre)}`);
  console.log('offset:', Math.round(Math.abs(centre - width / 2)), 'px');
});
