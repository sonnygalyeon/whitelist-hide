import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHealth, friendlyError, parseSelection, verifiedSelection, probePassed } from '../src/state.js';
const healthy = 'session_present=true\nrunning=true\nengine_alive=true\nnetwork_resource=true\n';
test('active session requires every component', () => {
  assert.equal(parseHealth(healthy).running, true);
  for (const key of ['session_present', 'engine_alive', 'network_resource', 'running']) {
    assert.equal(parseHealth(healthy.replace(`${key}=true`, `${key}=false`)).running, false);
  }
});
test('stale heartbeat cannot be presented as active', () => {
  assert.equal(parseHealth(healthy + 'stale=true').running, false);
});
test('failed helper output is not a stopped session', () => {
  for (const text of ['ok', '', 'permission denied', 'running=false']) assert.throws(() => parseHealth(text));
});
test('cancellation and early engine exit give actionable errors', () => {
  assert.match(friendlyError('UAC cancelled 1223'), /администратора/);
  assert.match(friendlyError('engine exited before runtime ownership'), /Лог движка/);
});

const probes = { results: ['youtube-web', 'youtube-image', 'discord-api', 'discord-cdn'].map(target => ({ target, ok: true })) };
const selected = { request_id: 'request1', outcome: 'connected', message: 'HTTPS проверен', session_id: 'session1', strategy: 'split', attempts: [{ strategy: 'split', probes, confirmation: probes }] };
test('old request and unconfirmed success cannot be shown as connected', () => {
  assert.throws(() => parseSelection(JSON.stringify(selected), 'request2'));
  assert.throws(() => parseSelection(JSON.stringify({ ...selected, session_id: null }), 'request1'));
  assert.throws(() => parseSelection(JSON.stringify({ ...selected, attempts: [{ strategy: 'split', probes }] }), 'request1'));
  assert.equal(parseSelection(JSON.stringify(selected), 'request1').outcome, 'connected');
});
test('verified status belongs to exactly one living session', () => {
  const report = parseSelection(JSON.stringify(selected));
  assert.equal(verifiedSelection(report, { running: true, sessionId: 'session1' }), true);
  assert.equal(verifiedSelection(report, { running: false, sessionId: 'session1' }), false);
  assert.equal(verifiedSelection(report, { running: true, sessionId: 'session2' }), false);
  assert.equal(verifiedSelection(report, { running: true }), false);
});
test('each target is required and duplicate successes do not count', () => {
  assert.equal(probePassed({ results: [] }), false);
  assert.equal(probePassed({ results: probes.results.slice(1) }), false);
  assert.equal(probePassed({ results: [...probes.results, probes.results[0]] }), false);
  assert.equal(probePassed(probes), true);
});
