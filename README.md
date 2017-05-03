[![npm version](https://badge.fury.io/js/cmr1-ssl-validator.svg)](https://www.npmjs.com/package/cmr1-ssl-validator)
[![build status](https://travis-ci.org/cmr1/node-ssl-validator.svg?branch=master)](https://travis-ci.org/cmr1/node-ssl-validator)

# node-ssl-validator
Scan and validate SSL certificates

### Table of contents
- [CLI](#cli)
  - [Install](#install-globally)
  - [Help](#show-help)
  - [Basic example](#basic-cli-example)
  - [Advanced example](#advanced-cli-example)  
- [Module](#module)
  - [Install](#install-locally)
  - [Help](#show-help)
  - [Basic example](#basic-code-example)
  - [Advanced example](#advanced-code-example)  
- [Hooks](#hooks)
  - [Hook arguments](#hook-arguments)
  - [Success example](#success-example)
  - [Failure example](#failure-example)

## CLI

#### Install globally:
```bash
npm install -g cmr1-ssl-validator
```

#### Show help:
```bash
ssl-validator --help
```

#### Basic cli example:
```bash
# Scan & validate current directory
ssl-validator 

# Scan & validate default Let's Encrypt directory
ssl-validator /etc/letsencrypt/live --recursive

# Scan & validate default dehydrated directory
ssl-validator /etc/dehydrated/certs --recursive
```

#### Advanced cli example:
```bash
ssl-validator \
  # Use recursive flag to group certs by directory
  --recursive \

  # Scan & validate default dehydrated directory
  --directory /etc/dehydrated/certs \          
  
  # Provide cert & key file regular expressions
  --certfile "^(fullchain|cert).pem$" \
  --keyfile "^privkey.pem$" \

  # Provide expiration period in days
  --time 30 \

  # Provide a slack webhook URL for notifications
  --slack https://hooks.slack.com/services/foo/bar/foobar \

  # Provide an executable hook to trigger with invalid certificate info
  --hook /usr/bin/foo-bar
```

[Back to Top](#node-ssl-validator)

## Module

#### Install locally:
```bash
npm install --save cmr1-ssl-validator
```

#### Basic code example:
```javascript
// Require cmr1-ssl-validator module
const SslValidator = require('cmr1-ssl-validator');

// Create a new validator with default options
const validator = new SslValidator();

// Run validator with default options
validator.run(err => {
  if (err) {
    // Something went wrong
    validator.error(err);
  } else {
    // All finished
    validator.log('Finished.');
  }
});
```

#### Advanced code example:
```javascript
// Require cmr1-ssl-validator module
const SslValidator = require('cmr1-ssl-validator');

// Create a new validator with default options
const validator = new SslValidator({
  // Use recursive flag to group certs by directory
  recursive: true,

  // Scan & validate default dehydrated directory
  directory: '/etc/dehydrated/certs',

  // Provide cert & key file regular expressions
  certfile: '^(fullchain|cert).pem$',
  keyfile: '^privkey.pem$',

  // Provide expiration period in days
  time: 30,

  // Provide a slack webhook URL for notifications
  slack: 'https://hooks.slack.com/services/foo/bar/foobar',

  // Provide an executable hook to trigger with invalid certificate info
  hook: '/usr/bin/foo-bar'
});

// Run validator with default options
validator.run(err => {
  if (err) {
    // Something went wrong
    validator.error(err);
  } else {
    // All finished
    validator.log('Finished.');
  }
});
```

[Back to Top](#node-ssl-validator)

## Hooks
An executable can be called after completion with information about failure(s).

#### Hook arguments:
```bash
/path/to/hook EXIT_CODE [DOMAIN_LIST]
```

- `EXIT_CODE` is the exit status of the validator (`0` or `1`)
- `DOMAIN_LIST` a list of invalid domains, grouped by certificate
  - Domains are joined by `,`
  - Groups are joined by `;`
  - **Example:** `abc.co,www.abc.co;xyz.co,www.xyz.co`
    - *Two certs: `abc.co` & `xyz.co`, both with alternate domain name: `www.`*

#### Success example:
```bash
/path/to/hook 0
```

#### Failure example:
```bash
/path/to/hook 1 abc.co,www.abc.co;xyz.co,www.xyz.co
```

[Back to Top](#node-ssl-validator)
