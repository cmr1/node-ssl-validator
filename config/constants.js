'use strict';

module.exports = {
  REQUIRED_OPTIONS: [
    'directory',
    'certfile',
    'keyfile',
    'time'
  ],
  GROUP_FILE: {
    REGEX_CERTFILE: '^(.*)\.(cer|crt|bundle)$',
    REGEX_KEYFILE: '^(.*)\.(key|priv|privkey)$'
  },
  GROUP_DIR: {
    REGEX_CERTFILE: '^(fullchain|cert)\.pem$',
    REGEX_KEYFILE: '^privkey\.pem$'
  }
}