'use strict';

const assert = require('assert');
const traverse = require('traverse');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { decode } = require('he');
const debug = require('debug')('mongoose-dompurify');

const window = (new JSDOM('')).window;
const sanitizer = createDOMPurify(window);

const defaults = {
  skip: ['_id', 'createdAt', 'updatedAt'],
  encodeHtmlEntities: false,
  sanitizer: undefined
};

module.exports = exports = function sanitizerPlugin (schema, options = defaults) {
  assert.ok(Array.isArray(options.skip), "'skip' must be an array");

  debug('registering plugin on schema with options', options);

  const sanitize = (val) => sanitizer.sanitize(val, options.sanitizer);

  schema.pre('save', function (next) {
    const model = this;

    const doc = JSON.parse(JSON.stringify(this.toJSON()));

    debug('running pre:save hook', doc);

    // Sanitize every node in tree
    const sanitized = traverse(doc).map(function (node) {
      const path = this.path.join('.');
      debug('checking', path);

      if (typeof node === 'string' && options.skip.indexOf(path) === -1) {
        let sanitizedNode = sanitize(node);
        if (!options.encodeHtmlEntities) {
          sanitizedNode = decode(sanitizedNode);
        }
        if (sanitizedNode !== node) {
          model.set(path, sanitizedNode);
          debug(`Sanitized ${path} from "${node}" to "${sanitizedNode}"`);
        }
      }
    });

    next();
  });
};
