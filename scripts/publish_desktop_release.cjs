const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const expectedAssets = [
  'White-Hide-Windows-Setup.exe',
  'White-Hide-Windows-Setup.msi',
  'White-Hide-Windows-Portable.zip',
  'White-Hide-macOS-arm64.dmg',
  'White-Hide-macOS-intel.dmg',
  'White-Hide-Linux.AppImage',
  'White-Hide-Linux.deb',
  'White-Hide-Linux.rpm',
];

function collectAssets(root) {
  const files = new Map();
  function walk(dir) {
    for (const item of fs.readdirSync(dir, {withFileTypes: true})) {
      const file = path.join(dir, item.name);
      if (item.isDirectory()) walk(file);
      else {
        if (!expectedAssets.includes(item.name)) throw new Error(`Unexpected asset: ${file}`);
        if (files.has(item.name)) throw new Error(`Duplicate asset: ${item.name}`);
        if (!fs.statSync(file).size) throw new Error(`Empty asset: ${file}`);
        files.set(item.name, file);
      }
    }
  }
  walk(root);
  for (const name of expectedAssets) {
    if (!files.has(name)) throw new Error(`Missing release asset: ${name}`);
  }
  return files;
}

module.exports = async ({github, context, core}) => {
  const files = collectAssets('release-assets');
  const config = JSON.parse(fs.readFileSync('apps/desktop/src-tauri/tauri.conf.json', 'utf8'));
  const version = config.version;
  const tag = `v${version}`;
  if (context.ref.startsWith('refs/tags/') && context.ref !== `refs/tags/${tag}`) {
    throw new Error(`Tag must match desktop version: ${tag}`);
  }
  const marker = `Source commit: ${context.sha}`;
  const prerelease = version.includes('-');
  const body = [
    `White Hide ${version}`, '', marker,
    `Build: https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
    '', 'Windows x64: Setup.exe / Setup.msi or the complete Portable.zip.',
    'macOS: choose arm64 for Apple Silicon or intel for Intel Macs.',
    'Linux x64: AppImage, deb and rpm (built on Ubuntu 24.04).', '',
    'All packages include the platform engine, helper and default profiles.',
    'SHA256SUMS.txt contains download checksums.', '',
    'Validation: Rust formatting, Clippy and tests on Windows/macOS/Linux; frontend tests; '
      + 'real engine profile validation; native start/stop, duplicate-start rejection and watchdog rollback.',
    '', 'Installers are unsigned; Apple notarization is not configured. '
      + 'Windows Portable requires WebView2. Linux requires nftables and polkit. '
      + 'Installed GUI dialogs, updates/uninstallation and connectivity in user networks still require testing.',
    prerelease ? 'This is a release candidate (Pre-release).' : '',
  ].filter(Boolean).join('\n\n');
  let release;
  try {
    release = (await github.rest.repos.getReleaseByTag({...context.repo, tag})).data;
  } catch (error) {
    if (error.status !== 404) throw error;
    release = (await github.rest.repos.createRelease({
      ...context.repo, tag_name: tag, target_commitish: context.sha,
      name: `White Hide ${version}`, body, prerelease, draft: true,
    })).data;
  }
  if (!release.body?.includes(marker)) {
    throw new Error(`${tag} belongs to another commit. Bump the version before publishing new binaries.`);
  }
  const sums = [];
  const upload = async (name, data) => {
    const digest = `sha256:${crypto.createHash('sha256').update(data).digest('hex')}`;
    const existing = release.assets.find(asset => asset.name === name);
    if (existing) {
      if (existing.digest !== digest || existing.size !== data.length) {
        throw new Error(`Existing release asset differs: ${name}`);
      }
      return;
    }
    await github.rest.repos.uploadReleaseAsset({...context.repo, release_id: release.id, name, data});
  };
  for (const [name, file] of files) {
    const data = fs.readFileSync(file);
    sums.push(`${crypto.createHash('sha256').update(data).digest('hex')}  ${name}`);
    await upload(name, data);
  }
  await upload('SHA256SUMS.txt', Buffer.from(sums.sort().join('\n') + '\n'));
  const assets = (await github.rest.repos.listReleaseAssets({...context.repo, release_id: release.id, per_page: 100})).data;
  for (const name of [...expectedAssets, 'SHA256SUMS.txt']) {
    if (!assets.some(asset => asset.name === name && asset.state === 'uploaded' && asset.size > 0)) {
      throw new Error(`Upload is incomplete: ${name}`);
    }
  }
  await github.rest.repos.updateRelease({...context.repo, release_id: release.id, draft: false});
  await core.summary.addLink('Download White Hide', release.html_url).write();
};
module.exports.collectAssets = collectAssets;
module.exports.expectedAssets = expectedAssets;
