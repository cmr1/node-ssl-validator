'use strict';

const fs = require('fs');
const path = require('path');
const exec = require('child_process').exec;
const async = require('async');
const Slack = require('slack-node');
const Cmr1Aws = require('cmr1-aws');
const Cmr1Logger = require('cmr1-logger');
const config = require('../config');

class SslValidator extends Cmr1Logger {
  constructor(options) {
    super();

    this.enableLogging(config.cli.logging);

    this.options = Object.assign({}, config.defaults, options || {});

    this.ses = new Cmr1Aws.SES();
    this.slack = new Slack();
    this.failures = [];
    this.groupList = [];
    this.notifications = {};

    if (!this.options.certfile) {
      this.options.certfile = this.options.recursive ? config.constants.GROUP_DIR.REGEX_CERTFILE : config.constants.GROUP_FILE.REGEX_CERTFILE;
    }

    if (!this.options.keyfile) {
      this.options.keyfile = this.options.recursive ? config.constants.GROUP_DIR.REGEX_KEYFILE : config.constants.GROUP_FILE.REGEX_KEYFILE;
    }

    this.fileTypes = {
      x509: new RegExp(this.options.certfile),
      rsa: new RegExp(this.options.keyfile)
    };
  }

  run(callback) {
    this.ensureOptions(err => {
      if (err) return callback(err);

      const dirs = Array.isArray(this.options.directory) ? this.options.directory : [ this.options.directory ];

      async.each(dirs, (dir, next) => {
        this.findStats(dir, (err, stats) => {
          if (err) return next(err);
          
          if (stats.isDirectory()) {
            this.processDir(stats.realPath, next);
          } else {
            this.warn(`${dir} is not a directory!`);
            return next();
          }
        });
      }, err => {
        if (err) return callback(err);

        if (this.failures.length === 0) {
          const totalGroups = this.groupList.length;
          const totalFiles = this.groupList.reduce((sum, group) => (sum + group.files.length), 0);

          if (totalGroups > 0) {
            this.queueNotification('good', {
              title: 'SSL certificates look good!',
              value: `Validated ${totalGroups} certificate(s) - Processed ${totalFiles} file(s)`,
              short: false
            });
          }
        }

        this.notify(callback);
      });
    });
  }

  queueNotification(status, field) {
    if (typeof this.notifications[status] === 'undefined') {
      this.notifications[status] = [];
    }

    field.value = field.value.replace(' - ', "\n");

    this.notifications[status].push(field);
  }

  processDir(path, callback) {
    this.scan(path, (err, groups) => {
      if (err) return callback(err);

      async.each(Object.keys(groups), (key, next) => {
        const group = groups[key];

        this.validateGroup(group, err => {
          if (err) {
            const status = err.status || 'warning';
            const msg = err.msg || 'No Message';

            this.warn(msg);

            this.queueNotification(status, {
              title: group.domains ? group.domains.join(', ') : 'Unknown',
              value: msg,
              short: false
            });
            
            this.failures.push({
              err,
              group
            });
          }

          if (group.files && group.files.length > 0) {
            this.groupList.push(group);
          }

          return next();
        });
      }, callback);
    });
  }

  scan(dir, callback) {
    this.debug(`Scanning dir: ${dir}`);

    fs.readdir(dir, (err, files) => {
      if (err) return callback(err);

      const groups = {};

      async.each(files, (file, next) => {
        this.findStats(path.join(dir, file), (err, stats) => {
          if (err) return next(err);

          if (stats.isDirectory()) {
            if (this.options.recursive) {
              return this.processDir(stats.realPath, next);
            } else {
              this.debug(`Ignoring directory: '${file}'. Set --recursive option to scan recursively.`);

              return next();
            }
          } else if (this.fileTypes.x509.test(file) || this.fileTypes.rsa.test(file)) {
            const fileParts = file.split('.');

            fileParts.pop();
            
            const groupKey = this.options.recursive ? dir : path.join(dir, fileParts.join('.'));

            if (typeof groups[groupKey] === 'undefined') {
              groups[groupKey] = {
                key: groupKey,
                mod: null,
                files: [],
                domains: null
              }
            }

            groups[groupKey].files.push(path.join(dir, file));

            return next();
          } else {
            this.debug(`Skipping file: ${file}`);
            return next();
          }
        });
      }, err => {
        if (err) return callback(err);

        return callback(null, groups);
      });
    });
  }

  validateGroup(group, callback) {
    if (group.files && Array.isArray(group.files)) {
      this.debug(`Validating group: ${group.key}`);

      async.each(group.files, (file, next) => {
        const msgPrefix = `File: ${file} - `;
        const type = this.fileTypes.rsa.test(path.basename(file)) ? 'rsa' : 'x509';

        const flags = [
          '-noout',
          '-modulus'
        ];

        if (type === 'x509') {
          flags.push('-dates');
          flags.push('-text');
          flags.push('-certopt no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_subject,no_issuer,no_pubkey,no_sigdump,no_aux')
        }

        const cmd = `openssl ${type} ${flags.join(' ')} -in ${file}`;

        exec(cmd, (error, stdout, stderr) => {
          if (error) return next({
            status: 'danger',
            msg: `Command failed: - ${cmd}`
          });

          if (stderr) {
            this.warn(stderr);
          }

          this.debug(stdout);

          const modMatches = stdout.match(/Modulus\=([^\s]+)/);
          const dnsMatches = stdout.match(/DNS\:([^,|\s]+)/g);
          const dateMatches = stdout.match(/(not(Before|After)\=.*)/g);

          if (dnsMatches && dnsMatches.length > 0) {
            const domains = dnsMatches.map(domain => domain.substr(4).trim());

            if (!group.domains) {
              group.domains = domains;
            } else if (group.domains.sort().join(',') !== domains.sort().join(',')) {
              return next({
                status: 'danger',
                msg: `${msgPrefix}Domain mismatch: "${group.domains.sort().join(',')}" != "${domains.sort().join(',')}"`
              });
            }
          }

          if (dateMatches && dateMatches.length > 1) {
            // 30day * 24hr * 60min * 60sec * 1000ms
            const expireDiff = this.options.time * 24 * 60 * 60 * 1000;
            const notBeforeStr = dateMatches[0].split('=')[1];
            const notAfterStr = dateMatches[1].split('=')[1];
            const notBefore = new Date(notBeforeStr).getTime();
            const notAfter = new Date(notAfterStr).getTime();
            const now = new Date().getTime();

            if (notBefore > now) {
              return next({
                status: 'danger',
                msg: `${msgPrefix}Not valid before: ${notBeforeStr}`
              });
            } else if (now >= notAfter) {
              return next({
                status: 'danger',
                msg: `${msgPrefix}Expired: ${notAfterStr}`
              });
            } else if (now >= (notAfter - expireDiff)) {
              return next({
                status: 'warning',
                msg: `${msgPrefix}Expires: ${notAfterStr}`
              });
            }
          } else if (type === 'x509') {
            return next({
              status: 'danger',
              msg: `${msgPrefix}Unable to obtain dates`
            });
          }

          if (modMatches && modMatches.length > 1) {
            if (!group.mod) {
              group.mod = modMatches[1];
              return next();
            } else if (group.mod !== modMatches[1]) {
              this.warn(`Group MOD = "${group.mod}"`);
              this.warn(` File MOD = "${modMatches[1]}"`);
              return next({
                status: 'danger',
                msg: `${msgPrefix}Modulus mismatch`
              });
            } else {
              return next();
            }
          } else {
            return next({
              status: 'danger',
              msg: `${msgPrefix}Unable to obtain modulus`
            });
          }
        });
      }, err => {
        if (err) return callback(err);

        if (group.files.length > 0) {
          this.success(`Validated: ${group.key} | (${group.domains.join(', ')})`);
        }

        return callback();
      });
    } else {
      return callback({
        status: 'danger',
        msg: `Group: '${group}' is missing files`
      });
    }
  }

  findStats(path, callback) {
    fs.realpath(path, (err, realPath) => {
      if (err) return callback(err);

      if (realPath !== path) {
          this.debug(`Path: '${path}' resolves to: '${realPath}'`);        
      }

      fs.lstat(realPath, (err, stats) => {
        if (err) return callback(err);

        stats.realPath = realPath;

        return callback(null, stats);
      });
    });
  }

  slackMessage(status, fields, callback) {
    if (this.options.slack && this.slack) {
      const allowedStatuses = [ 'good', 'danger', 'warning' ];
      const color = allowedStatuses.indexOf(status) !== -1 ? status : 'warning';

      this.slack.setWebhook(this.options.slack);

      this.slack.webhook({
        icon_emoji: ':lock:',
        username: 'ssl-validator',
        attachments: [
          {
            fallback: 'SSL Validation Message',
            color,
            fields
          }
        ]
      }, (err, resp) => {
        if (err) return callback(err);

        this.debug('Slack webhook response:', resp);

        return callback();
      });
    } else {
      return callback();
    }
  }

  emailMessage(status, fields, callback) {
    if (this.options.email && this.ses) {

    }
  }

  notify(callback) {
    async.each(Object.keys(this.notifications), (status, next) => {
      this.slackMessage(status, this.notifications[status], next);
    }, err => {
      if (err) return callback(err);

      return callback();
    });
  }

  ensureOptions(callback) {
    config.constants.REQUIRED_OPTIONS.forEach(option => {
      if (typeof this.options[option] === 'undefined') {
        return callback(`Missing required option: '${option}'`);
      }
    });

    return callback();
  }
}

module.exports = SslValidator;