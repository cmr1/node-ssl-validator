'use strict';

const fs = require('fs');
const path = require('path');
const exec = require('child_process').exec;
const async = require('async');
const Slack = require('slack-node');
const Cmr1Cli = require('cmr1-cli');

const requiredOptions = [
  'directory',
  'certfile',
  'keyfile',
  'time'
];

class SslValidator extends Cmr1Cli {
  constructor(options) {
    super(options);

    this.slack = new Slack();
    this.failures = [];
    this.groupList = {};
    this.fileTypes = {
      x509: new RegExp(this.options.certfile),
      rsa: new RegExp(this.options.keyfile)
    };

    if (this.options.slack) {
      this.slack.setWebhook(this.options.slack);
    }
  }

  run() {
    this.ensureOptions(err => {
      if (err) this.fail(err);

      const dirs = Array.isArray(this.options.directory) ? this.options.directory : [ this.options.directory ];

      async.each(dirs, (dir, next) => {
        this.findStats(dir, (err, stats) => {
          if (err) return next(err);
          
          if (stats.isDirectory()) {
            this.processGroup(stats.realPath, next);
          } else {
            this.warn(`${dir} is not a directory!`);
            return next();
          }
        });
      }, err => {
        if (err) {
          this.fail(err);
        } else if (this.failures.length > 0) {
          this.failures.forEach(failure => {
            this.error(`Invalid: ${failure.dir || 'Unknown'}`);
          });
          this.fail(`Failed with ${this.failures.length} error(s)`);
        } else {
          this.finish('Finished.');
        }
      });
    });
  }

  processGroup(path, callback) {
    this.scan(path, (err, group) => {
      if (err) return callback(err);

      this.validateGroup(group, err => {
        if (err) {
          this.warn(err);
          this.failures.push(`${group.dir}::${err}`);
        }

        return callback();
      });
    });
  }

  scan(dir, callback) {
    this.debug(`Scanning dir: ${dir}`);

    fs.readdir(dir, (err, files) => {
      if (err) return callback(err);

      const group = {
        dir,
        mod: null,
        files: []
      };

      async.each(files, (file, next) => {
        this.findStats(path.join(dir, file), (err, stats) => {
          if (err) return next(err);

          if (stats.isDirectory()) {
            if (this.options.recursive) {
              this.processGroup(stats.realPath, next);
            } else {
              this.debug(`Ignoring directory: '${file}'. Set --recursive option to scan recursively.`);

              return next();
            }
          } else if (this.fileTypes.x509.test(file) || this.fileTypes.rsa.test(file)) {
            group.files.push(path.join(dir, file));

            return next();
          } else {
            this.debug(`Skipping file: ${file}`);
            return next();
          }
        });
      }, err => {
        if (err) return callback(err);

        return callback(null, group);
      });
    });
  }

  validateGroup(group, callback) {
    if (group.files && Array.isArray(group.files)) {
      this.debug('Validating group:'+group.dir);
      async.each(group.files, (file, next) => {
        const cmd = this.fileTypes.rsa.test(path.basename(file)) ? 'rsa' : 'x509';

        const flags = [
          '-noout',
          '-modulus'
        ];

        if (cmd === 'x509') {
          flags.push('-dates');
        }

        exec(`openssl ${cmd} ${flags.join(' ')} -in ${file}`, (error, stdout, stderr) => {
          if (error) return next(error);

          if (stderr) {
            this.warn(stderr);
          }

          this.debug(stdout);

          const modMatches = stdout.match(/Modulus\=([^\s]+)/i);
          const dateMatches = stdout.match(/(not(Before|After)\=.*)/gi);

          if (dateMatches && dateMatches.length > 1) {
            // 30day * 24hr * 60min * 60sec * 1000ms
            const expireDiff = this.options.time * 24 * 60 * 60 * 1000;
            const notBeforeStr = dateMatches[0].split('=')[1];
            const notAfterStr = dateMatches[1].split('=')[1];
            const notBefore = new Date(notBeforeStr).getTime();
            const notAfter = new Date(notAfterStr).getTime();
            const now = new Date().getTime();

            if (notBefore > now) {
              return next(`Certificate file: ${file} is not valid before: ${notBeforeStr}`);
            } else if (now >= notAfter) {
              return next(`Certificate file: ${file} is not valid after: ${notAfterStr}`);
            } else if (now >= (notAfter - expireDiff)) {
              return next(`Certificate file: ${file} is expiring in < ${this.options.time} days!`);
            }
          } else if (cmd === 'x509') {
            return next(`Unable to obtain dates from file: ${file}`);
          }

          if (modMatches && modMatches.length > 1) {
            if (!group.mod) {
              group.mod = modMatches[1];
              return next();
            } else if (group.mod !== modMatches[1]) {
              this.warn(`Group MOD = "${group.mod}"`);
              this.warn(` File MOD = "${modMatches[1]}"`);
              return next(`Modulus mismatch!`)
            } else {
              this.debug(`Validated file: ${file}`);
              return next();
            }
          } else {
            return next(`Unable to obtain modulus from file: ${file}`);
          }
        });
      }, err => {
        if (err) return callback(err);

        if (group.files.length > 0) {
          this.success(`Validated: ${group.dir}`);
        }

        return callback();
      });
    } else {
      return callback(`Group: '${group}' is missing files`);
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

  hook(code, callback) {
    if (this.options.hook) {
      this.debug(`Executing hook: ${this.options.hook}`);

      this.findStats(this.options.hook, (err, stats) => {
        if (err) return callback(err);

        exec(`${this.options.hook} ${code} "${this.failures.join(';;')}"`, (error, stdout, stderr) => {
          if (error) return callback(error);

          this.log(stdout);

          if (stderr) {
            this.warn(stderr);
          }

          return callback();
        });
      });
    } else {
      return callback();
    }
  }

  fail(msg, code=1) {
    this.error(msg);

    this.hook(code, err => {
      if (err) this.error(err);

      if (this.options.slack && this.slack) {
        async.each(this.failures, (failure, next) => {
          const parts = failure.split('::');
          const group = parts[0] || 'Unknown';
          const msg = parts[1] || 'Unknown';

          this.slack.webhook({
            icon_emoji: ':lock:',
            username: 'ssl-validator',
            attachments: [
              {
                fallback: 'SSL Validation Failure!',
                pretext: 'SSL Validation Failure!',
                color: '#D00000',
                fields: [
                  {
                    title: group,
                    value: msg,
                    short: false
                  }
                ]
              }
            ]
          }, (err, resp) => {
            if (err) return next(err);

            this.debug(resp);

            return next();
          });
        }, err => {
          if (err) this.error(err);

          process.exit(code);          
        });
        
      } else {
        process.exit(code);
      }
    });
  }

  finish(msg, code=0) {
    this.success(msg);

    this.hook(code, err => {
      if (err) {
        this.fail(err);
      } else {
        process.exit(code);
      }
    });
  }

  ensureOptions(callback) {
    requiredOptions.forEach(option => {
      if (typeof this.options[option] === 'undefined') {
        return callback(`Missing required option: '${option}'`);
      }
    });

    return callback();
  }
}

module.exports = SslValidator;