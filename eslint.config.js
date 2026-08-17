import js from '@eslint/js'
import globals from 'globals'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist/', 'docs/']),
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: globals.node,
    },
    rules: {
      curly: ['error', 'multi-line'],
      eqeqeq: 'error',
      'default-case': 'error',
      'default-case-last': 'error',
      'prefer-const': 'error',
      'no-unused-vars': [
        'error',
        {
          varsIgnorePattern: '^_',
          argsIgnorePattern: '^_',
        },
      ],
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'assert',
              message: 'Prefer importing node:assert/strict.',
            },
            {
              name: 'node:assert',
              message: 'Prefer importing node:assert/strict.',
            },
          ],
        },
      ],
      'no-var': 'error',
    },
  },
])
