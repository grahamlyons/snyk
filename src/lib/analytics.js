module.exports = analytics;
module.exports.single = postAnalytics;

const snyk = require('../lib');
const config = require('./config');
const version = require('./version');
const request = require('./request');
const isCI = require('./is-ci').isCI;
const debug = require('debug')('snyk');
const os = require('os');
const osName = require('os-name');
const crypto = require('crypto');
const uuid = require('uuid');
const stripAnsi = require('strip-ansi');

const metadata = {};
// analytics module is required at the beginning of the CLI run cycle
const startTime = Date.now();

function analytics(data) {
  if (!data) {
    data = {};
  }

  // merge any new data with data we picked up along the way
  if (Array.isArray(data.args)) {
    // this is an overhang from the cli/args.js and we don't want it
    delete (data.args.slice(-1).pop() || {})._;
  }

  if (Object.keys(metadata).length) {
    data.metadata = metadata;
  }

  return postAnalytics(data);
}

function postAnalytics(data) {
  // if the user opt'ed out of analytics, then let's bail out early
  // ths applies to all sending to protect user's privacy
  if (snyk.config.get('disable-analytics') || config.DISABLE_ANALYTICS) {
    debug('analytics disabled');
    return Promise.resolve();
  }

  // get snyk version
  return version().then(function (version) {
    data.version = version;
    data.os = osName(os.platform(), os.release());
    data.nodeVersion = process.version;

    const seed = uuid.v4();
    const shasum = crypto.createHash('sha1');
    data.id = shasum.update(seed).digest('hex');

    const headers = {};
    if (snyk.api) {
      headers.authorization = 'token ' + snyk.api;
    }

    data.ci = isCI();
    data.durationMs = Date.now() - startTime;

    debug('analytics', data);

    return request({
      body: {
        data: data,
      },
      url: config.API + '/analytics/cli',
      json: true,
      method: 'post',
      headers: headers,
    });
  }).catch(function (error) {
    debug('analytics', error); // this swallows the analytics error
  });
}

analytics.add = function (key, value) {
  if (typeof value === 'string') {
    value = stripAnsi(value);
  }
  if (metadata[key]) {
    if (!Array.isArray(metadata[key])) {
      metadata[key] = [metadata[key]];
    }
    metadata[key].push(value);
  } else {
    metadata[key] = value;
  }
};
