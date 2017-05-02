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
      description: 'Directory to scan (default = ".")', 
      typeLabel: '[underline]{directory}' 
    },
    {
      name: 'certfile',
      alias: 'c',
      type: RegExp,
      defaultValue: '^(fullchain|cert)\.pem$',
      description: 'RegExp for certificate filenames (default = "^(fullchain|cert)\.pem$")'
    },
    {
      name: 'keyfile',
      alias: 'k',
      type: RegExp,
      defaultValue: '^privkey\.pem$',
      description: 'RegExp for private key filenames (default = "^privkey\.pem$")'
    },
    {
      name: 'time',
      alias: 't',
      type: Number,
      defaultValue: 30,
      description: 'Time (in days) to consider certificate [bold]{expiring} (default = 30)',
      typeLabel: '[underline]{days}'
    },
    {
      name: 'hook',
      alias: 'e',
      type: String,
      description: 'Hook to execute when completed',
      typeLabel: '[underline]{/path/to/hook}'
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