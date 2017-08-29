'use strict';

const should = require('chai').should();
const mongoose = require('mongoose');
const sanitizerPlugin = require('../lib/');

const xss_string = 'Something & something else > XSS<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>';
const no_xss_string = 'Something & something else > XSS';
const legitimate_string = '<script>Preserve this</script>';

mongoose.plugin(sanitizerPlugin, {
  skip: ['non_sanitizable_field']
});

mongoose.Promise = global.Promise;

const TestSchema = new mongoose.Schema({
  sanitizable_field: String,
  non_sanitizable_field: String,
  object_field: {
    sub_sanitizable_field: {
      type: String
    },
    sub_non_sanitizable_field: {
      type: String
    }
  },
  raw_object_field: Object
});

mongoose.model('Test', TestSchema);

const Test = mongoose.model('Test');

const testDoc = new Test({
  sanitizable_field: xss_string,
  non_sanitizable_field: legitimate_string,
  object_field: {
    sub_sanitizable_field: xss_string
  },
  raw_object_field: {
    sanitizable_field: xss_string,
    object_field: {
      sanitizable_field: xss_string
    }
  }
});

describe('Mongoose Sanitizer Tests', () => {
  before(function(done) {
    mongoose.connect('mongodb://localhost/test', { useMongoClient: true }, (err) => {
      should.not.exist(err);
      done();
    });
  });

  after(() => {
    mongoose.connection.close();
  });

  it('should save a test document', () => testDoc.save((err) => {
    should.not.exist(err);
  }));

  it('should not sanitize skip fields', () => {
    testDoc.non_sanitizable_field.should.equal(legitimate_string);
  });

  it('should sanitize schema fields', () => {
    testDoc.sanitizable_field.should.equal(no_xss_string);
    testDoc.object_field.sub_sanitizable_field.should.equal(no_xss_string);
  });

  it('should sanitize non-schema sub-fields', () => {
    testDoc.raw_object_field.sanitizable_field.should.equal(no_xss_string);
    testDoc.raw_object_field.object_field.sanitizable_field.should.equal(no_xss_string);
  });
});
