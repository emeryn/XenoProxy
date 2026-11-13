import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import reactHooks from 'eslint-plugin-react-hooks';
import security from 'eslint-plugin-security';

export default [
  { ignores: ['dist', 'node_modules', 'playwright-report', 'test-results'] },
  js.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsparser,
      parserOptions: { ecmaVersion: 2022, sourceType: 'module', ecmaFeatures: { jsx: true } },
      globals: { window: 'readonly', document: 'readonly', navigator: 'readonly', console: 'readonly', crypto: 'readonly', fetch: 'readonly', URL: 'readonly', URLSearchParams: 'readonly', Blob: 'readonly', AbortSignal: 'readonly', Intl: 'readonly', localStorage: 'readonly' },
    },
    plugins: { '@typescript-eslint': tseslint, 'react-hooks': reactHooks, security },
    rules: {
      ...tseslint.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      'no-undef': 'off',
      'security/detect-object-injection': 'off',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-eval': 'error',
      'no-implied-eval': 'error',
    },
  },
];
