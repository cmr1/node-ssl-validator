'use strict';

const pkg = require('../package');
const defaults = require('./defaults');
const constants = require('./constants');

const optionDefinitions = [
  {
    name: 'recursive',
    alias: 'r',
    type: Boolean,
    description: 'Scan recursively & group by directory'
  },
  { 
    name: 'directory', 
    alias: 'd', 
    type: String, 
    multiple: true, 
    defaultOption: true, 
    description: 'Directory to scan', 
    typeLabel: '[underline]{directory}' 
  },
  {
    name: 'certfile',
    alias: 'c',
    type: RegExp,
    description: 'RegExp for certificate filenames'
  },
  {
    name: 'keyfile',
    alias: 'k',
    type: RegExp,
    description: 'RegExp for private key filenames'
  },
  {
    name: 'time',
    alias: 't',
    type: Number,
    description: 'Time (in days) to consider certificate [bold]{expiring}',
    typeLabel: '[underline]{days}'
  },
  {
    name: 'slack',
    alias: 's',
    type: String,
    description: 'Slack webhook URL to post notifications',
    typeLabel: '[underline]{url}'
  },
  {
    name: 'hook',
    alias: 'e',
    type: String,
    description: 'Hook to execute when completed',
    typeLabel: '[underline]{/path/to/hook}'
  },
  {
    name: 'acm',
    alias: 'a',
    type: Boolean,
    description: 'Validate certificates on AWS ACM'
  }
];

Object.keys(defaults).forEach(option => {
  const defaultValue = defaults[option];
  const optionDef = optionDefinitions.filter(def => def.name === option)[0];

  if (optionDef) {
    optionDef.defaultValue = defaults[option];
    optionDef.description += ` (Default = "${defaults[option]}")`;

    // if (constants.REQUIRED_OPTIONS.indexOf(option) !== -1) {
    //   optionDef.description += "\t REQUIRED";
    // }
  }
});

module.exports = {
  name: pkg.name || 'CMR1 SSL Validator',
  version: pkg.version || '0.0.1',
  description: pkg.description || 'Scan and validate SSL certificate(s)',
  helpSections: {
    usage: [
      'ssl-validator [[underline]{directory}] [[underline]{options}]',
      'ssl-validator -d [[underline]{directory}] [[underline]{options}]',
      'ssl-validator --directory [[underline]{directory}] [[underline]{options}]'
    ],
    examples: [
      '# Group by filename (default):',
      'ssl-validator /etc/nginx/certs',
      '',
      '# Group by directory (recursive):',
      'ssl-validator /etc/dehydrated/certs --recursive',
      '',
      '# Example using available options:',
      'ssl-validator \\',
      '--recursive \\',
      '--directory /etc/dehydrated/certs \\',
      `--certfile "${constants.GROUP_DIR.REGEX_CERTFILE}" \\`,
      `--keyfile "${constants.GROUP_DIR.REGEX_KEYFILE}" \\`,
      `--time ${defaults.time} \\`,
      '--slack https://hooks.slack.com/services/foo/bar/foobar \\',
      '--hook /usr/bin/foo-bar \\',
      '--acm'
    ]
  },
  helpHeader: 'Available Options',
  optionDefinitions,
  logging: {
    log: {
      stamp: true,
      prefix: "",
      color: "white"
    },
    warn: {
      stamp: true,
      throws: false,
      prefix: "WARN:",
      color: "yellow"
    },
    error: {
      stamp: true,
      throws: false,
      prefix: "ERROR:",
      color: "red"
    },
    debug: {
      stamp: true,
      verbose: true,
      prefix: "DEBUG:",
      color: "cyan"
    },
    success: {
      stamp: true,
      prefix: "SUCCESS:",
      color: "green"
    }
  }
};