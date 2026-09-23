import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHealth, friendlyError } from '../src/state.js';
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
