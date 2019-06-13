import * as Debug from 'debug';
import * as depGraphLib from '@snyk/dep-graph';
import * as snyk from '../lib';
import {apiTokenExists} from './api-token';
import * as request from './request';
import * as config from './config';
import * as os from 'os';
import * as _ from 'lodash';
import {isCI} from './is-ci';
import * as analytics from './analytics';
import { SingleDepRootResult, MonitorError, DepTree } from './types';
import * as projectMetadata from './project-metadata';
import * as path from 'path';

const debug = Debug('snyk');

// TODO(kyegupov): clean up the type, move to snyk-cli-interface repository

interface MonitorBody {
  meta: Meta;
  policy: string;
  package: DepTree;
  target: {};
  targetFileRelativePath: string;
  targetFile: string;
}

interface Meta {
  method?: string;
  hostname: string;
  id: string;
  ci: boolean;
  pid: number;
  node: string;
  master: boolean;
  name: string;
  version: string;
  org?: string;
  pluginName: string;
  pluginRuntime: string;
  dockerImageId?: string;
  dockerBaseImage?: string;
  projectName: string;
}

function dropEmptyDeps(node: DepTree) {
  if (node.dependencies) {
    const keys = Object.keys(node.dependencies);
    if (keys.length === 0) {
      delete node.dependencies;
    } else {
      for (const k of keys) {
        dropEmptyDeps(node.dependencies[k]);
      }
    }
  }
}

function countTotalDependenciesInTree(depTree: DepTree): number {
  let count = 0;
  for (const dep of _.values(depTree.dependencies || {})) {
    if (dep) {
      count++;
      count += countTotalDependenciesInTree(dep);
    }
  }
  return count;
}

async function pruneTree(tree: DepTree, packageManagerName: string): Promise<DepTree> {
  debug('pruning dep tree');
  // pruning is easiest when going from graph to tree
  // yes, this is slow
  const graph = await depGraphLib.legacy.depTreeToGraph(tree, packageManagerName);
  const prunedTree: DepTree = await depGraphLib.legacy
    .graphToDepTree(graph, packageManagerName, {prune: true}) as DepTree;
  // make sure these survive
  if (tree.docker) {
    prunedTree.docker = tree.docker;
  }
  if (tree.packageFormatVersion) {
    prunedTree.packageFormatVersion = tree.packageFormatVersion;
  }
  if (tree.targetFile) {
    prunedTree.targetFile = tree.targetFile;
  }
  debug('finished pruning dep tree');
  return prunedTree;
}

export async function monitor(root: string, meta: any, info: SingleDepRootResult, targetFile?: string): Promise<any> {
  apiTokenExists();
  let prePruneDepCount;
  if (meta.prune) {
    debug('prune used, counting total dependencies');
    prePruneDepCount = countTotalDependenciesInTree(info.package);
    analytics.add('prePruneDepCount', prePruneDepCount);
    debug('total dependencies: %d', prePruneDepCount);
  }
  const pkg = meta.prune
    ? await pruneTree(info.package, meta.packageManager)
    : info.package;

  const pluginMeta = info.plugin;
  let policy;
  const policyPath = meta['policy-path'] || root;
  const policyLocations = [policyPath].concat(pluckPolicies(pkg))
      .filter(Boolean);
  // docker doesn't have a policy as it can be run from anywhere
  if (!meta.isDocker || !policyLocations.length) {
    await snyk.policy.create();
  }
  policy = await snyk.policy.load(policyLocations, {loose: true});

  const packageManager = meta.packageManager;
  if (packageManager === 'gomod') {
    throw new Error('Monitoring go.mod files is not supported yet.');
  }
  analytics.add('packageManager', packageManager);

  const target = await projectMetadata.getInfo(pkg);
  const targetFileRelativePath = targetFile ? path.relative(root, targetFile) : '';

  dropEmptyDeps(pkg);

  // TODO(kyegupov): async/await
  return new Promise((resolve, reject) => {
    request({
      body: {
        meta: {
          method: meta.method,
          hostname: os.hostname(),
          id: meta.id || snyk.id || pkg.name,
          ci: isCI(),
          pid: process.pid,
          node: process.version,
          master: snyk.config.isMaster,
          name: pkg.name,
          version: pkg.version,
          org: config.org ? decodeURIComponent(config.org) : undefined,
          pluginName: pluginMeta.name,
          pluginRuntime: pluginMeta.runtime,
          dockerImageId: pluginMeta.dockerImageId,
          dockerBaseImage: pkg.docker ? pkg.docker.baseImage : undefined,
          dockerfileLayers: pkg.docker ? pkg.docker.dockerfileLayers : undefined,
          projectName: meta['project-name'],
          prePruneDepCount, // undefined unless 'prune' is used
        },
        policy: policy ? policy.toString() : undefined,
        package: pkg,
        // we take the targetFile from the plugin,
        // because we want to send it only for specific package-managers
        target,
        targetFile: pluginMeta.targetFile,
        targetFileRelativePath,
      } as MonitorBody,
      gzip: true,
      method: 'PUT',
      headers: {
        'authorization': 'token ' + snyk.api,
        'content-encoding': 'gzip',
      },
      url: config.API + '/monitor/' + packageManager,
      json: true,
    }, (error, res, body) => {
      if (error) {
        return reject(error);
      }

      if (res.statusCode === 200 || res.statusCode === 201) {
        resolve(body);
      } else {
        const e = new MonitorError('Server returned unexpected error for the monitor request. ' +
            `Status code: ${res.statusCode}, response: ${res.body.userMessage || res.body.message}`);
        e.code = res.statusCode;
        e.userMessage = body && body.userMessage;
        if (!e.userMessage && res.statusCode === 504) {
          e.userMessage = 'Connection Timeout';
        }
        reject(e);
      }
    });
  });
}

function pluckPolicies(pkg) {
  if (!pkg) {
    return null;
  }

  if (pkg.snyk) {
    return pkg.snyk;
  }

  if (!pkg.dependencies) {
    return null;
  }

  return _.flatten(Object.keys(pkg.dependencies).map((name) => {
    return pluckPolicies(pkg.dependencies[name]);
  }).filter(Boolean));
}
