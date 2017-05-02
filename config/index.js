'use strict';

const pkg = require('../package');

module.exports = {
  name: pkg.name || 'CMR1 SSL Validator',
  description: pkg.description || 'Scan and validate SSL certificate(s)',
  helpHeader: 'Available Options',
  optionDefinitions: [
    {
      name: 'recursive',
      alias: 'r',
      type: Boolean,
      defaultValue: false,
      description: 'Scan recursively'
    },
    { 
      name: 'directory', 
      alias: 'd', 
      type: String, 
      multiple: true, 
      defaultOption: true, 
      defaultValue: '.',
      description: 'Directory to scan', 
      typeLabel: '[underline]{directory}' 
    },
    {
      name: 'certfile',
      alias: 'c',
      type: RegExp,
      defaultValue: '^(fullchain|cert)\.pem$',
      description: 'RegExp for certificate filenames (OpenSSL cmd: [underline]{x509})'
    },
    {
      name: 'keyfile',
      alias: 'k',
      type: RegExp,
      defaultValue: '^privkey\.pem$',
      description: 'RegExp for private key filenames (OpenSSL cmd: [underline]{rsa})'
    },
    {
      name: 'expiration',
      alias: 'e',
      type: Number,
      defaultValue: 30,
      description: 'Number of days to consider certificate "expiring"',
      typeLabel: '[underline]{days}'
    }
  ],
  logging: {
    warn: {
      throws: false
    },
    error: {
      throws: false
    },
    test: {
      verbose: true,  // Consider this debug, only show when verbose
      throws: false,  // Should this log type throw an Error?
      stamp: true,    // Also prefix log output with a timestamp
      prefix: 'Test', // Prefix string to show before each log msg
      color: 'blue'   // Color of output text (FG only)
    }
  }
};