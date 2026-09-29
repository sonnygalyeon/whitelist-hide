const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const publish = require('../publish_desktop_release.cjs');

function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'white-hide-release-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.mkdirSync(path.join(root, 'release-assets'));
  for (const name of publish.expectedAssets) {
    fs.writeFileSync(path.join(root, 'release-assets', name), `fixture: ${name}`);
  }
  fs.mkdirSync(path.join(root, 'apps/desktop/src-tauri'), {recursive: true});
  fs.writeFileSync(path.join(root, 'apps/desktop/src-tauri/tauri.conf.json'),
    JSON.stringify({version: '1.0.0-rc.2'}));
  const state = {release: options.release, uploads: new Map(), publications: 0};
  const github = {rest: {repos: {
    async getReleaseByTag() {
      if (!state.release) throw Object.assign(new Error('Not Found'), {status: 404});
      return {data: state.release};
    },
    async createRelease(args) {
      assert.equal(args.draft, true);
      state.release = {...args, id: 42, assets: [], html_url: 'https://example.test/release'};
      return {data: state.release};
    },
    async uploadReleaseAsset({name, data}) {
      if (name === options.failUpload) throw new Error('Upload interrupted');
      state.uploads.set(name, data);
      state.release.assets.push({name, size: data.length, state: 'uploaded',
        digest: `sha256:${crypto.createHash('sha256').update(data).digest('hex')}`});
    },
    async listReleaseAssets() {
      const assets = structuredClone(state.release.assets);
      return {data: options.alterAssets ? options.alterAssets(assets) : assets};
    },
    async updateRelease(args) {
      assert.equal(args.draft, false);
      state.publications++;
      state.release.draft = false;
    },
  }}};
  const core = {summary: {addLink() {return this;}, async write() {}}};
  const context = {ref: 'refs/heads/main', sha: '1234567890abcdef', runId: 10,
    repo: {owner: 'fixture', repo: 'white-hide'}};
  return {root, state, context, run: () => publish({github, context, core, root})};
}

test('publishes all eight packages and matching checksum file before opening the release', async t => {
  const f = fixture(t);
  await f.run();
  assert.equal(f.state.publications, 1);
  assert.equal(f.state.release.prerelease, true);
  assert.equal(f.state.release.tag_name, 'v1.0.0-rc.2');
  assert.equal(f.state.release.target_commitish, f.context.sha);
  assert.match(f.state.release.body, /Автоподбор для сетей РФ/);
  assert.equal(f.state.uploads.size, 9);
  const sums = f.state.uploads.get('SHA256SUMS.txt').toString().trim().split('\n');
  assert.equal(sums.length, 8);
  for (const line of sums) {
    const [digest, name] = line.split('  ');
    assert.equal(digest, crypto.createHash('sha256').update(f.state.uploads.get(name)).digest('hex'));
  }
});

test('missing platform package prevents creation of a release', async t => {
  const f = fixture(t);
  fs.unlinkSync(path.join(f.root, 'release-assets/White-Hide-macOS-intel.dmg'));
  await assert.rejects(f.run, /Missing release asset/);
  assert.equal(f.state.release, undefined);
});

test('tag and desktop version must match', async t => {
  const f = fixture(t);
  f.context.ref = 'refs/tags/v1.0.0-rc.1';
  await assert.rejects(f.run, /Tag must match desktop version/);
  assert.equal(f.state.release, undefined);
});

test('a release from another commit is never overwritten', async t => {
  const f = fixture(t, {release: {body: 'Source commit: previous', assets: []}});
  await assert.rejects(f.run, /belongs to another commit/);
  assert.equal(f.state.uploads.size, 0);
  assert.equal(f.state.publications, 0);
});

test('resuming the same release verifies existing files without uploading duplicates', async t => {
  const f = fixture(t);
  await f.run();
  await f.run();
  assert.equal(f.state.release.assets.length, 9);
  f.state.release.assets[0].digest = 'sha256:changed';
  await assert.rejects(f.run, /Existing release asset differs/);
});

test('an interrupted upload leaves the release in draft', async t => {
  const f = fixture(t, {failUpload: 'White-Hide-macOS-arm64.dmg'});
  await assert.rejects(f.run, /Upload interrupted/);
  assert.equal(f.state.publications, 0);
  assert.equal(f.state.release.draft, true);
});

for (const [name, alterAssets] of Object.entries({
  'wrong digest': assets => {assets[0].digest = 'sha256:changed'; return assets;},
  'wrong size': assets => {assets[0].size++; return assets;},
  'unfinished upload': assets => {assets[0].state = 'new'; return assets;},
  'missing file': assets => assets.slice(1),
  'duplicate filename': assets => [...assets, assets[0]],
})) {
  test(`${name} prevents opening the release`, async t => {
    const f = fixture(t, {alterAssets});
    await assert.rejects(f.run, /Upload verification failed/);
    assert.equal(f.state.publications, 0);
    assert.equal(f.state.release.draft, true);
  });
}
