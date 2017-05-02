'use strict';

const fs = require('fs');
const path = require('path');
const exec = require('child_process').exec;
const async = require('async');
const Cmr1Cli = require('cmr1-cli');

const requiredOptions = [
  'directory',
  'certfile',
  'keyfile',
  'expiration'
];

class SslValidator extends Cmr1Cli {
  constructor(options) {
    super(options);
    this.groupList = {};
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
            this.scan(stats.realPath, (err, group) => {
              if (err) return next(err);

              this.validateGroup(group, next);
            });
          } else {
            this.warn(`${dir} is not a directory!`);
            return next();
          }
        });
      }, callback);
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
              this.scan(stats.realPath, (err, group) => {
                if (err) return next(err);

                this.validateGroup(group, next);
              });
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
            const expireDiff = this.options.expiration * 24 * 60 * 60 * 1000;
            const notBefore = new Date(dateMatches[0].split('=')[1]).getTime();
            const notAfter = new Date(dateMatches[1].split('=')[1]).getTime();
            const now = new Date().getTime();

            if (notBefore > now) {
              return next(`Certificate file: ${file} is not valid before: ${notBefore}`);
            } else if (now >= notAfter) {
              return next(`Certificate file: ${file} is not valid after: ${notAfter}`);
            } else if (now >= (notAfter - expireDiff)) {
              return next(`Certificate file: ${file} is expiring in < ${this.options.expiration} days!`);
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

  fail(msg, code=1) {
    this.error(msg);
    process.exit(code);
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