const config = require('../config')
const exec = require('child_process').exec
const Cmr1Cli = require('cmr1-cli')
const SslValidator = require('../')

class SslValidatorCli extends Cmr1Cli {
  constructor () {
    super(config.cli)

    this.validator = new SslValidator(this.options)
  }

  run () {
    this.validator.run(err => {
      if (err) {
        this.fail(err)
      } else if (this.validator.failures.length > 0) {
        this.validator.failures.forEach(failure => {
          this.error(failure.err.msg || failure)
        })

        this.fail(`Failed with ${this.validator.failures.length} error(s)`)
      } else {
        this.finish('Finished.')
      }
    })
  }

  hook (code, callback) {
    if (this.options.hook) {
      this.debug(`Executing hook: ${this.options.hook}`)

      this.validator.findStats(this.options.hook, (err, stats) => {
        if (err) return callback(err)

        const failedDomains = this.validator.failures.map(failure => {
          const domainsArray = failure.group.domains

          if (domainsArray.length > 1 && domainsArray[0].indexOf('*.') === 0) {
            domainsArray.reverse()
          }

          return domainsArray.join(',')
        }).join(';')

        this.debug('Failed domains:', failedDomains)

        exec(`${this.options.hook} ${code} "${failedDomains}"`, (error, stdout, stderr) => {
          if (error) return callback(error)

          this.log(stdout)

          if (stderr) {
            this.warn(stderr)
          }

          return callback()
        })
      })
    } else {
      return callback()
    }
  }

  fail (msg) {
    this.finish(msg, 1)
  }

  finish (msg, code = 0) {
    this.log(msg)

    this.hook(code, err => {
      if (err) {
        this.error(err)
        process.exit(1)
      } else {
        process.exit(code)
      }
    })
  }
}

module.exports = SslValidatorCli
