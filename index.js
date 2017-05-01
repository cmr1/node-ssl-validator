'use strict';

const config = require('./config');
const SslChecker = require('./src/ssl-checker');

const sslChecker = new SslChecker(config);

sslChecker.run(err => {
  if (err) sslChecker.fail(err);

  sslChecker.log(sslChecker.fileList);

  sslChecker.success('Finished');
});
