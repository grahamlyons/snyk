module.exports = patch;

var now = new Date();

var debug = require('debug')('snyk');
var chalk = require('chalk');
var glob = require('glob');
var tempfile = require('tempfile');
var fs = require('then-fs');
var path = require('path');
var _ = require('lodash');
var applyPatch = require('./apply-patch');
var stripVersions = require('./strip-versions');
var getVulnSource = require('./get-vuln-source');
var dedupe = require('./dedupe-patches');
var writePatchFlag = require('./write-patch-flag');
var spinner = require('../spinner');
var errors = require('../errors/legacy-errors');
var analytics = require('../analytics');
var getPatchFile = require('./fetch-patch');

function patch(vulns, live) {
  var lbl = 'Applying patches...';
  var errorList = [];

  return spinner(lbl).then(function () {
    // the target directory where our module name will live
    vulns.forEach((vuln) => vuln.source = getVulnSource(vuln, live));

    var deduped = dedupe(vulns);
    debug('patching %s vulns after dedupe', deduped.packages.length);

    // find the patches, pull them down off the web, save them in a temp file
    // then apply each individual patch - but do it one at a time (via reduce)
    var promises = deduped.packages.reduce(function (acc, vuln) {
      return acc.then(function (res) {
        var patches = vuln.patches; // this is also deduped in `dedupe`

        if (patches === null) {
          debug('no patch available for ' + vuln.id);
          analytics.add('no-patch', vuln.from.slice(1).join(' > '));
          return res;
        }

        analytics.add('patch', vuln.from.slice(1).join(' > '));
        debug(`Patching vuln: ${vuln.id} ${vuln.from}`);

        // the colon doesn't like Windows, ref: https://git.io/vw2iO
        var fileSafeId = vuln.id.replace(/:/g, '-');
        var flag = path.resolve(vuln.source, '.snyk-' + fileSafeId + '.flag');
        var oldFlag = path.resolve(vuln.source, '.snyk-' + vuln.id + '.flag');

        // get the patches on the local fs
        var promises = patches.urls.map(function (url) {
          var filename = tempfile('.' + fileSafeId + '.snyk-patch');
          return getPatchFile(url, filename).then(function (patch) {
            // check whether there's a trace of us having patched before
            return fs.exists(flag).then(function (exists) {
              // if the file doesn't exist, look for the old style filename
              // in case and for backwards compatability
              return exists || fs.exists(oldFlag);
            }).then(function (exists) {
              if (!exists) {
                return patch;
              }
              debug('Previous flag found = ' + exists +
              ' | Restoring file back to original to apply the patch again');
              // else revert the patch
              return new Promise(function (resolve, reject) {
                // find all backup files that do not belong to transitive deps
                glob('**/*.orig', {cwd: vuln.source, ignore: '**/node_modules/**'}, function (error, files) {
                  if (error) {
                    return reject(error);
                  }

                  // copy '.orig' backups over the patched files
                  for (const file of files) {
                    const backupFile = path.resolve(vuln.source, file);
                    const sourceFile = backupFile.slice(0, -'.orig'.length);
                    debug('restoring', backupFile, sourceFile);
                    fs.renameSync(backupFile, sourceFile);
                  }

                  resolve(patch);
                });
              });
            });
          }).then(function (patch) {
            if (patch === false) {
              debug('already patched %s', vuln.id);
              return vuln;
            }

            debug('applying patch file for %s: \n%s\n%s', vuln.id, url, patch);

            return applyPatch(patch, vuln, live, url)
              .then(function () {
                return true;
              }, function (e) {
                errorList.push(e);
                return false;
              })
              .then(writePatchFlag(now, vuln))
              .then(function (ok) {
                return ok ? vuln : false;
              });
          });
        });

        return Promise.all(promises).then(function (result) {
          res.push(result);
          return res; // this is what makes the waterfall reduce chain work
        });
      });
    }, Promise.resolve(deduped.removed));

    var promise = promises.then(function (res) {
      var patched = _.flatten(res).filter(Boolean);

      if (!live) {
        debug('[skipping - dry run]');
        return patched;
      }
      return Promise.all(patched);
    }).then(function (patched) {
      var config = {};

      // this reduce function will look to see if the patch actually resolves
      // more than one vulnerability, and if it does, it'll replicate the
      // patch rule against the *other* vuln.ids. This will happen when the user
      // runs the wizard and selects to apply a patch that fixes more than one
      // vuln.
      var mapped = patched.map(patchRule).reduce(function (acc, curr, i) {
        var vuln = patched[i];
        if (vuln.grouped && vuln.grouped.includes) {
          vuln.grouped.includes.forEach(function (id) {
            var rule = _.cloneDeep(curr);
            rule.vulnId = id;
            acc.push(rule);
          });
        }

        acc.push(curr);

        return acc;
      }, []);

      config.patch = mapped.reduce(function (acc, curr) {
        if (!acc[curr.vulnId]) {
          acc[curr.vulnId] = [];
        }

        var id = curr.vulnId;
        delete curr.vulnId;
        acc[id].push(curr);

        return acc;
      }, {});

      debug('patched', config);

      return config;
    });

    return promise;
  })
    // clear spinner in case of success or failure
    .then(spinner.clear(lbl))
    .catch(function (error) {
      spinner.clear(lbl)();
      throw error;
    })
    .then(function (res) {
      if (errorList.length) {
        errorList.forEach(function (error) {
          console.log(chalk.red(errors.message(error)));
          debug(error.stack);
        });
        throw new Error('Please email support@snyk.io if this problem persists.');
      }

      return res;
    });
}

function patchRule(vuln) {
  var rule = {
    vulnId: vuln.id,
  };
  rule[stripVersions(vuln.from.slice(1)).join(' > ')] = {
    patched: now.toJSON(),
  };
  return rule;
}
