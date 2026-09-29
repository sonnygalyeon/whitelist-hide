export function parseHealth(text) {
  const values = Object.fromEntries(String(text).split(/\r?\n/).map(line => line.split('=', 2)).filter(pair => pair.length === 2));
  for (const key of ['running', 'engine_alive', 'network_resource', 'session_present']) {
    if (!['true', 'false'].includes(values[key])) throw new Error('Некорректный ответ системного помощника');
  }
  const engine = values.engine_alive === 'true';
  const network = values.network_resource === 'true';
  const session = values.session_present === 'true';
  const stale = values.stale === 'true';
  return { sessionId: values.session_id || null, running: values.running === 'true' && session && engine && network && !stale, session, engine, network, stale };
}

export function friendlyError(error) {
  const raw = String(error ?? 'Неизвестная ошибка');
  const text = raw.toLowerCase();
  if (/pkexec|authorization|administrator|uac|отмен|cancel|1223/.test(text)) return 'Нет подтверждения администратора. Повторите операцию и подтвердите системный запрос. На Linux требуется работающий агент polkit.';
  if (/sha256|untrusted artifact|artifact error|integrity/.test(text)) return 'Проверка целостности компонентов не пройдена. Переустановите полный пакет приложения.';
  if (/already|occupied/.test(text)) return 'Есть незавершённая сессия или конфликт сетевых ресурсов. Нажмите «Остановить и восстановить сеть».';
  if (/exited before/.test(text)) return 'Движок завершился при запуске. Откройте «Лог движка», чтобы увидеть причину.';
  return raw;
}

const requiredTargets = ['youtube-web', 'youtube-image', 'discord-api', 'discord-cdn'];
export function probePassed(report) {
  return Array.isArray(report?.results) && requiredTargets.every(id => {
    const matches = report.results.filter(r => r.target === id);
    return matches.length === 1 && matches[0].ok === true;
  });
}
export function parseSelection(text, requestId = null) {
  const report = JSON.parse(text);
  if (report === null && requestId === null) return null;
  if (!report || !['checking', 'connected', 'failed'].includes(report.outcome) ||
      typeof report.message !== 'string' || !Array.isArray(report.attempts) ||
      (requestId !== null && report.request_id !== requestId)) {
    throw new Error('Некорректный или устаревший результат подбора стратегии');
  }
  if (report.outcome === 'connected') {
    const last = report.attempts.at(-1);
    if (!report.session_id || !report.strategy || last?.strategy !== report.strategy ||
        !probePassed(last.probes) || !probePassed(last.confirmation)) {
      throw new Error('Доступ не подтверждён двумя проверками');
    }
  }
  return report;
}
export function verifiedSelection(report, health) {
  return health.running && report?.outcome === 'connected' &&
    Boolean(health.sessionId) && report.session_id === health.sessionId;
}
