'use strict';

const expect = require('chai').expect;

const SslValidatorCli = require('../src/ssl-validator-cli');

describe('SslValidatorCli', function () {
    it('should exist', function () {
        expect(SslValidatorCli).to.exist;
    });
});
