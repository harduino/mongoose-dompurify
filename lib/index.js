'use strict';

const assert = require('assert');
const traverse = require('traverse');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = (new JSDOM('')).window;
const sanitizer = createDOMPurify(window);

const defaults = {
  include: [],
  skip: [],
  sanitizer: undefined
};

module.exports = exports = function sanitizerPlugin (schema, options = defaults) {
  assert.ok(Array.isArray(options.include), "'include' must be an array");
  assert.ok(Array.isArray(options.skip), "'skip' must be an array");

  const sanitize = (val) => sanitizer.sanitize(val, options.sanitizer);

  schema.pre('save', function (next) {
    const doc = JSON.parse(JSON.stringify(this._doc));

    if (options.include.length === 0) {
      // Sanitize every field by default
      options.include = Object.keys(this._doc);
    }

    // Sanitize every node in tree
    const sanitized = traverse(doc).map(function (node) {
      if (typeof node === 'string') {
        const sanitizedNode = sanitize(node);
        this.update(sanitizedNode);
      }
    });

    // Exclude skipped nodes
    options.include.forEach(function (node) {
      // Sanitize field unless explicitly excluded
      if (options.skip.indexOf(node) < 0) {
        this[node] = sanitized[node];
      }
    }, this);

    next();
  });
};
