'use strict';

const fs = require('fs');
const path = require('path');
const async = require('async');
const Cmr1Cli = require('cmr1-cli');

const requiredOptions = [
  'directory'
];

class SslChecker extends Cmr1Cli {
  constructor(options) {
    super(options);
    this.fileList = {};
  }

  run(callback) {
    this.validate(err => {
      if (err) return callback(err);

      const dirs = Array.isArray(this.options.directory) ? this.options.directory : [ this.options.directory ];

      async.each(dirs, (dir, next) => {
        this.findStats(dir, (err, stats) => {
          if (err) return next(err);
          
          if (stats.isDirectory()) {
            this.scan(stats.realPath, next);
          } else {
            this.warn(`${dir} is not a directory!`);
            return next();
          }
        });
      }, callback);
    });
  }

  scan(dir, callback) {
    this.log(`Scanning dir: ${dir}`);

    fs.readdir(dir, (err, files) => {
      if (err) return callback(err);

      async.each(files, (file, next) => {
        this.findStats(path.join(dir, file), (err, stats) => {
          if (err) return next(err);

          if (stats.isDirectory()) {
            if (this.options.recursive) {
              this.scan(stats.realPath, next);
            } else {
              this.debug(`Ignoring directory: '${file}'. Set --recursive option to scan recursively.`);

              return next();
            }
          } else if (/^.*\.pem$/.test(file)) {
            if (!this.fileList[dir]) {
              this.fileList[dir] = [];
            }
            
            this.fileList[dir].push(file);

            return next();
          } else {
            this.debug(`Skipping file: ${file}`);
            return next();
          }
        });
      }, callback);
    });
  }

  verify() {

  }

  findStats(path, callback) {
    fs.realpath(path, (err, realPath) => {
      if (err) return callback(err);

      if (realPath !== path) {
          this.warn(`Path: '${path}' resolves to: '${realPath}'`);        
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

  validate(callback) {
    if (!this.required(this.options, requiredOptions)) {
      return callback('Missing required option(s)');
    }

    return callback();
  }

  required(obj, keys) {
    keys.forEach(k => {
      if (typeof obj[k] === 'undefined') {
        this.warn(`Missing required option: '${k}'`);
        return false;
      }
    });

    return true;
  }
}

module.exports = SslChecker;