#!/usr/bin/env node
'use strict';

/*
 * verify-npm-integrity.js
 *
 * Checks whether the npm installed on this machine still matches the files npm
 * actually published for that version.
 *
 * Why this exists: some infostealers persist by patching npm's own CLI in place,
 * so every later `npm` command re-runs their payload. The patched file keeps its
 * name and location, and `npm -v` keeps reporting the expected version, because
 * that version string is just text in a file the attacker now controls.
 *
 * This script never runs npm. It reads npm's files directly, downloads the
 * official tarball for the same version, verifies that download against the
 * registry's own integrity hash, and compares the two trees file by file.
 *
 * Zero dependencies, on purpose: on a machine whose npm you don't trust,
 * `npm install` is not an option.
 *
 * Usage:
 *   node verify-npm-integrity.js
 *   node verify-npm-integrity.js --npm-dir "C:\\Users\\you\\AppData\\Roaming\\nvm\\v20.13.0\\node_modules\\npm"
 *   node verify-npm-integrity.js --scan-nvm
 *   node verify-npm-integrity.js --json
 *
 * Exit codes:
 *   0  npm's own files match what was published
 *   1  npm's own files (lib/, bin/, index.js) have been modified
 *   3  only bundled dependencies differ - worth reviewing, often vendor patching
 *   2  the check could not be completed
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const https = require('https');
const crypto = require('crypto');

const REGISTRY = 'https://registry.npmjs.org';

// npm's own source, as opposed to the dependencies it bundles. A modification
// here is the thing this script is actually looking for.
const NPM_ITSELF = /^(lib\/|bin\/|index\.js$|package\.json$)/;

// Present on disk but never in the tarball, for ordinary reasons.
const BENIGN_EXTRA = [
  /(^|\/)\.package-lock\.json$/,
  /(^|\/)\.bin(\/|$)/,
  /(^|\/)\.npmrc$/,
  /(^|\/)\.DS_Store$/,
  /(^|\/)node_modules\/\.cache(\/|$)/,
];

/* ------------------------------------------------------------------ args - */

function parseArgs(argv) {
  const opts = { npmDir: null, scanNvm: false, json: false, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--npm-dir') opts.npmDir = argv[++i];
    else if (a.startsWith('--npm-dir=')) opts.npmDir = a.slice(10);
    else if (a === '--scan-nvm') opts.scanNvm = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--verbose') opts.verbose = true;
    else if (a === '-h' || a === '--help') {
      process.stdout.write(usage());
      process.exit(0);
    } else {
      fail(`unknown argument: ${a}\n\n${usage()}`);
    }
  }
  return opts;
}

function usage() {
  return [
    'verify-npm-integrity.js - check a global npm install against the published tarball',
    '',
    '  --npm-dir <path>   check this npm directory instead of the one next to this node',
    '  --scan-nvm         find and check every nvm-managed npm on this machine',
    '  --json             machine-readable output',
    '  --verbose          list whitespace-only and missing files individually',
    '  -h, --help         this text',
    '',
  ].join('\n');
}

/* ------------------------------------------------------------- locating - */

function isNpmDir(dir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    return pkg.name === 'npm' && typeof pkg.version === 'string';
  } catch {
    return false;
  }
}

function defaultNpmDir() {
  const nodeDir = path.dirname(process.execPath);
  const candidates =
    process.platform === 'win32'
      ? [path.join(nodeDir, 'node_modules', 'npm')]
      : [
          path.join(nodeDir, '..', 'lib', 'node_modules', 'npm'),
          path.join(nodeDir, 'node_modules', 'npm'),
        ];
  for (const c of candidates) {
    const resolved = path.resolve(c);
    if (isNpmDir(resolved)) return resolved;
  }
  return null;
}

function findNvmNpmDirs() {
  const found = new Set();
  const roots = [];

  if (process.env.NVM_HOME) roots.push({ base: process.env.NVM_HOME, style: 'win' });
  roots.push({ base: path.join(os.homedir(), 'AppData', 'Roaming', 'nvm'), style: 'win' });
  if (process.env.NVM_DIR) {
    roots.push({ base: path.join(process.env.NVM_DIR, 'versions', 'node'), style: 'posix' });
  }
  roots.push({ base: path.join(os.homedir(), '.nvm', 'versions', 'node'), style: 'posix' });

  for (const { base, style } of roots) {
    let entries;
    try {
      entries = fs.readdirSync(base, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isDirectory() || !/^v?\d/.test(e.name)) continue;
      const dir =
        style === 'win'
          ? path.join(base, e.name, 'node_modules', 'npm')
          : path.join(base, e.name, 'lib', 'node_modules', 'npm');
      if (isNpmDir(dir)) found.add(path.resolve(dir));
    }
  }
  return [...found];
}

/* ---------------------------------------------------------------- http - */

function get(url, headers, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('too many redirects'));
    const options = { headers: Object.assign({ 'user-agent': 'verify-npm-integrity' }, headers) };
    https
      .get(url, options, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
          res.resume();
          return resolve(get(new URL(res.headers.location, url).toString(), headers, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`${url} returned HTTP ${res.statusCode}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

/* ----------------------------------------------------------------- tar - */

// Minimal tar reader. Handles ustar prefixes, PAX extended headers and GNU long
// names, which covers everything npm's tarballs have used.
function readTar(buf) {
  const files = new Map();
  let offset = 0;
  let pendingPath = null;

  const str = (b, start, len) => {
    const slice = b.subarray(start, start + len);
    const end = slice.indexOf(0);
    return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8');
  };

  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break; // end-of-archive marker

    const size = parseInt(str(header, 124, 12).trim(), 8) || 0;
    const type = String.fromCharCode(header[156] || 0x30);
    const body = buf.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;

    if (type === 'x' || type === 'X') {
      const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(body.toString('utf8'));
      if (m) pendingPath = m[1];
      continue;
    }
    if (type === 'L') {
      pendingPath = body.toString('utf8').replace(/\0+$/, '');
      continue;
    }
    if (type === 'g') continue;

    let name = pendingPath;
    pendingPath = null;
    if (name == null) {
      const prefix = str(header, 345, 155);
      const base = str(header, 0, 100);
      name = prefix ? `${prefix}/${base}` : base;
    }

    if (type !== '0' && type !== '\u0000') continue; // regular files only
    if (!name.startsWith('package/')) continue; // npm roots everything under package/

    files.set(name.slice('package/'.length), {
      exact: sha256(body),
      normal: sha256(normalize(body)),
    });
  }
  return files;
}

/* ---------------------------------------------------------- comparison - */

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Publishers, Node installers and distro packagers routinely reflow whitespace
// and line endings. Normalizing those away removes almost all of the noise
// without weakening the check: injected code is never whitespace-only.
function normalize(buf) {
  if (buf.includes(0)) return buf; // binary, leave it alone
  return Buffer.from(
    buf
      .toString('latin1')
      .replace(/\r\n/g, '\n')
      .replace(/[ \t]+$/gm, '')
      .replace(/\n+$/, '\n'),
    'latin1'
  );
}

function walk(dir, base = dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walk(full, base, out);
    else if (e.isFile()) out.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return out;
}

async function checkOne(npmDir, log) {
  const pkg = JSON.parse(fs.readFileSync(path.join(npmDir, 'package.json'), 'utf8'));
  const version = pkg.version;

  log(`npm directory : ${npmDir}`);
  log(`version       : ${version}  (read from package.json, never from "npm -v")`);

  // Timestamp pre-check. Not proof of anything by itself, but a CLI patched
  // after installation usually carries a modification time long after the rest
  // of the tree. An mtime *older* than the install is normal: archives preserve
  // the publisher's timestamps.
  const cli = path.join(npmDir, 'lib', 'cli.js');
  if (fs.existsSync(cli)) {
    const s = fs.statSync(cli);
    const skewDays = Math.round((s.mtimeMs - s.birthtimeMs) / 86400000);
    log(
      `lib/cli.js    : created ${s.birthtime.toISOString().slice(0, 10)}, ` +
        `modified ${s.mtime.toISOString().slice(0, 10)}` +
        (skewDays > 30 ? `  <-- rewritten ${skewDays} days after install` : '')
    );
  }

  const meta = JSON.parse(
    (await get(`${REGISTRY}/npm/${version}`, { accept: 'application/json' })).toString('utf8')
  );
  if (!meta.dist || !meta.dist.tarball) throw new Error(`registry has no tarball for npm@${version}`);

  const tgz = await get(meta.dist.tarball, {});

  // Verify the baseline before trusting it as a baseline.
  if (meta.dist.integrity) {
    const [alg, expected] = meta.dist.integrity.split('-');
    if (crypto.createHash(alg).update(tgz).digest('base64') !== expected) {
      throw new Error('downloaded tarball failed its registry integrity check');
    }
    log(`baseline      : npm-${version}.tgz verified against registry ${alg}`);
  } else if (meta.dist.shasum) {
    if (crypto.createHash('sha1').update(tgz).digest('hex') !== meta.dist.shasum) {
      throw new Error('downloaded tarball failed its registry shasum check');
    }
    log(`baseline      : npm-${version}.tgz verified against registry sha1`);
  }

  const published = readTar(zlib.gunzipSync(tgz));

  const modified = [];      // real content differences
  const cosmetic = [];      // whitespace or line endings only
  const unreadable = [];    // AV is holding the file
  const missing = [];
  const extra = [];

  for (const [rel, expected] of published) {
    const full = path.join(npmDir, rel);
    let buf;
    try {
      buf = fs.readFileSync(full);
    } catch (err) {
      if (err.code === 'ENOENT') missing.push(rel);
      else unreadable.push({ file: rel, code: err.code || err.message });
      continue;
    }
    if (sha256(buf) === expected.exact) continue;
    if (sha256(normalize(buf)) === expected.normal) cosmetic.push(rel);
    else modified.push({ file: rel, own: NPM_ITSELF.test(rel) });
  }

  const publishedSet = new Set(published.keys());
  for (const rel of walk(npmDir)) {
    if (publishedSet.has(rel)) continue;
    if (BENIGN_EXTRA.some((re) => re.test(rel))) continue;
    extra.push(rel);
  }

  modified.sort((a, b) => Number(b.own) - Number(a.own) || a.file.localeCompare(b.file));

  return {
    npmDir,
    version,
    comparedFiles: published.size,
    modified,
    cosmetic,
    unreadable,
    missing,
    extra,
  };
}

/* --------------------------------------------------------------- output - */

function report(r, log, verbose) {
  log(`compared      : ${r.comparedFiles} published files`);
  log('');

  const own = r.modified.filter((m) => m.own);
  const deps = r.modified.filter((m) => !m.own);

  if (r.unreadable.length) {
    log(`BLOCKED  ${r.unreadable.length} file(s) could not be read. Antivirus refusing access to a`);
    log(`         file inside npm is itself a finding, not an error:`);
    for (const u of r.unreadable) log(`           ${u.file}  (${u.code})`);
    log('');
  }

  if (own.length) {
    log(`FAIL     npm's own code does not match what npm published:`);
    log('');
    for (const m of own) log(`           ${m.file}`);
    log('');
    log(`         Nothing about a normal install, update or Node upgrade rewrites these`);
    log(`         files in place. Treat this machine's credentials as exposed and stop`);
    log(`         running npm on it.`);
  } else {
    log(`OK       npm's own code (lib/, bin/, index.js) matches the published tarball.`);
  }

  if (deps.length) {
    log('');
    log(`REVIEW   ${deps.length} bundled dependenc${deps.length === 1 ? 'y' : 'ies'} differ${deps.length === 1 ? 's' : ''} from npm's tarball:`);
    log('');
    for (const m of deps.slice(0, 20)) log(`           ${m.file}`);
    if (deps.length > 20) log(`           ... and ${deps.length - 20} more`);
    log('');
    log(`         Distributions and Node installers do backport security fixes into`);
    log(`         these, so this is not automatically bad. Worth an eyeball.`);
  }

  if (r.cosmetic.length) {
    log('');
    log(`ignored  ${r.cosmetic.length} file(s) differ only in whitespace or line endings.`);
    if (verbose) for (const f of r.cosmetic) log(`           ${f}`);
  }
  if (r.missing.length) {
    log(`ignored  ${r.missing.length} published file(s) absent on disk (installers strip docs and licenses).`);
    if (verbose) for (const f of r.missing) log(`           ${f}`);
  }
  if (r.extra.length) {
    log(`note     ${r.extra.length} file(s) on disk are not in the published tarball:`);
    for (const f of r.extra.slice(0, 10)) log(`           ${f}`);
    if (r.extra.length > 10) log(`           ... and ${r.extra.length - 10} more`);
  }
}

/* ------------------------------------------------------------------ main - */

function fail(msg) {
  process.stderr.write(`verify-npm-integrity: ${msg}\n`);
  process.exit(2);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const log = (s) => {
    if (!opts.json) process.stdout.write(`${s}\n`);
  };

  let dirs;
  if (opts.npmDir) {
    const dir = path.resolve(opts.npmDir);
    if (!isNpmDir(dir)) fail(`${dir} does not look like an npm install`);
    dirs = [dir];
  } else if (opts.scanNvm) {
    dirs = findNvmNpmDirs();
    if (!dirs.length) fail('no nvm-managed Node versions found. Pass --npm-dir <path> instead.');
  } else {
    const dir = defaultNpmDir();
    if (!dir) fail('could not locate the npm next to this node. Pass --npm-dir <path>.');
    dirs = [dir];
  }

  const results = [];
  let worst = 0;

  for (const dir of dirs) {
    log('');
    try {
      const r = await checkOne(dir, log);
      report(r, log, opts.verbose);
      results.push(r);
      if (r.modified.some((m) => m.own) || r.unreadable.length) worst = 1;
      else if (r.modified.length && worst === 0) worst = 3;
    } catch (err) {
      log(`ERROR    ${dir}: ${err.message}`);
      results.push({ npmDir: dir, error: err.message });
      worst = 2;
    }
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({ exitCode: worst, results }, null, 2)}\n`);
  } else {
    log('');
    log('This checks one thing: whether npm was modified on disk. A clean result does');
    log('not mean the machine is clean, and a dirty one means rotating credentials');
    log('from another device, not repairing the install.');
  }

  process.exit(worst);
}

main().catch((err) => fail(err.stack || err.message));