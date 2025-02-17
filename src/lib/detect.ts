import * as fs from 'then-fs';
import * as pathLib from 'path';
import * as debugLib from 'debug';
import * as _ from 'lodash';
import { NoSupportedManifestsFoundError } from './errors';
import { SupportedPackageManagers } from './package-managers';

const debug = debugLib('snyk-detect');

const DETECTABLE_FILES: string[] = [
  'yarn.lock',
  'package-lock.json',
  'package.json',
  'Gemfile',
  'Gemfile.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'build.sbt',
  'Pipfile',
  'requirements.txt',
  'Gopkg.lock',
  'vendor/vendor.json',
  'obj/project.assets.json',
  'project.assets.json',
  'packages.config',
  'paket.dependencies',
  'composer.lock',
];

// when file is specified with --file, we look it up here
const DETECTABLE_PACKAGE_MANAGERS: {
  [name: string]: SupportedPackageManagers;
} = {
  'Gemfile': 'rubygems',
  'Gemfile.lock': 'rubygems',
  '.gemspec': 'rubygems',
  'package-lock.json': 'npm',
  'pom.xml': 'maven',
  'build.gradle': 'gradle',
  'build.gradle.kts': 'gradle',
  'build.sbt': 'sbt',
  'yarn.lock': 'yarn',
  'package.json': 'npm',
  'Pipfile': 'pip',
  'requirements.txt': 'pip',
  'Gopkg.lock': 'golangdep',
  'go.mod': 'gomodules',
  'vendor.json': 'govendor',
  'project.assets.json': 'nuget',
  'packages.config': 'nuget',
  'project.json': 'nuget',
  'paket.dependencies': 'paket',
  'composer.lock': 'composer',
};

export function isPathToPackageFile(path) {
  for (const fileName of DETECTABLE_FILES) {
    if (_.endsWith(path, fileName)) {
      return true;
    }
  }
  return false;
}

export function detectPackageManager(root, options) {
  // If user specified a package manager let's use it.
  if (options.packageManager) {
    return options.packageManager;
  }
  // The package manager used by a docker container is not known ahead of time
  if (options.docker) {
    return undefined;
  }

  let packageManager;
  let file;
  if (isLocalFolder(root)) {
    if (options.file) {
      if (localFileSuppliedButNotFound(root, options.file)) {
        throw new Error(
          'Could not find the specified file: ' + options.file +
          '\nPlease check that it exists and try again.');
      }
      file = options.file;
      packageManager = detectPackageManagerFromFile(file);
    } else {
      debug('no file specified. Trying to autodetect in base folder ' + root);
      file = detectPackageFile(root);
      if (file) {
        packageManager = detectPackageManagerFromFile(file);
      }
    }
  } else {
    debug('specified parameter is not a folder, trying to lookup as repo');
    const registry = options.registry || 'npm';
    packageManager = detectPackageManagerFromRegistry(registry);
  }
  if (!packageManager) {
    throw NoSupportedManifestsFoundError([root]);
  }
  return packageManager;
}

// User supplied a "local" file, but that file doesn't exist
function localFileSuppliedButNotFound(root, file) {
  return file && fs.existsSync(root) &&
    !fs.existsSync(pathLib.resolve(root, file));
}

export function isLocalFolder(root) {
  try {
    return fs.lstatSync(root).isDirectory();
  } catch (e) {
    return false;
  }
}

export function detectPackageFile(root) {
  for (const file of DETECTABLE_FILES) {
    if (fs.existsSync(pathLib.resolve(root, file))) {
      debug('found package file ' + file + ' in ' + root);
      return file;
    }
  }

  debug('no package file found in ' + root);
}

function detectPackageManagerFromFile(file) {
  let key = pathLib.basename(file);

  if (/\.gemspec$/.test(key)) {
    key = '.gemspec';
  }

  if (!(key in DETECTABLE_PACKAGE_MANAGERS)) {
    // we throw and error here because the file was specified by the user
    throw new Error('Could not detect package manager for file: ' + file);
  }
  return DETECTABLE_PACKAGE_MANAGERS[key];
}

function detectPackageManagerFromRegistry(registry) {
  return registry;
}
