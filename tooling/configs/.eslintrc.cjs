module.exports = {
  env: { node: true, es2022: true },
  extends: ['eslint:recommended', 'plugin:security/recommended', 'prettier'],
  parserOptions: { ecmaVersion: 'latest' },
  plugins: ['security'],
  rules: {
    'no-eval': 'error',
    'security/detect-object-injection': 'off' // noisy for demo
  },
  ignorePatterns: ['node_modules', 'dist']
};
