import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { parseHealth, friendlyError } from './state.js';
import './style.css';

const $ = id => document.getElementById(id);
const descriptions = {
  standard: 'Базовая обработка HTTPS, QUIC и голосового трафика Discord.',
  split: 'Разделение TCP-пакетов; отдельная обработка QUIC и голосового трафика.',
  disorder: 'Изменение порядка частей TCP-пакета; отдельная обработка UDP.',
};
let busy = false;
let refreshing = false;
let available = false;
let health = { running: false, session: false, engine: false, network: false };
let known = false;
let native = isTauri();
let errorSticky = false;
let timer;

function event(message, tone = 'info') {
  const row = document.createElement('div');
  row.className = `event event-${tone}`;
  const time = document.createElement('span');
  time.className = 'event-time';
  time.textContent = new Date().toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' });
  const text = document.createElement('span');
  text.textContent = message;
  row.append(time, text);
  $('activity').prepend(row);
  while ($('activity').children.length > 100) $('activity').lastElementChild.remove();
}
function visual(kind, title, detail) {
  $('status-orb').dataset.state = kind;
  $('state').textContent = title;
  $('state-detail').textContent = detail;
  $('state-caption').textContent = { running: 'Сессия активна', error: 'Требуется внимание', busy: 'Выполняется операция', stopped: 'Сессия не активна' }[kind];
}
function controls() {
  $('toggle').disabled = !native || busy || refreshing || !known || (!health.session && !available);
  $('toggle').textContent = busy ? 'Подождите…' : health.session ? 'Отключить' : 'Включить';
  $('toggle').classList.toggle('danger', health.session);
  $('profile').disabled = busy || !known || health.session || !available;
  $('refresh').disabled = !native || busy || refreshing;
  $('recover').disabled = !native || busy || refreshing;
  $('export').disabled = !native || busy;
  $('show-logs').disabled = !native || busy;
}
function diagnostics() {
  $('diagnostics').replaceChildren();
  const items = [
    ['Компоненты приложения', available ? 'Встроенный профиль найден' : 'Не установлен полный пакет', available],
    ['Сетевой движок', known ? (health.engine ? 'Процесс работает' : 'Остановлен') : 'Состояние неизвестно', known && health.engine],
    ['Сетевой фильтр', known ? (health.network ? 'Ресурс активен' : 'Не активен') : 'Состояние неизвестно', known && health.network],
    ['Контроль сессии', health.stale ? 'Нет свежего ответа watchdog' : known ? 'Проверка завершена' : 'Проверка недоступна', known && !health.stale],
  ];
  for (const [label, value, ok] of items) {
    const row = document.createElement('div'); row.className = 'diagnostic';
    const dot = document.createElement('span'); dot.className = `dot dot-${ok ? 'ok' : 'warning'}`;
    const copy = document.createElement('div');
    const title = document.createElement('strong'); title.textContent = label;
    const detail = document.createElement('span'); detail.className = 'value'; detail.textContent = value;
    copy.append(title, detail); row.append(dot, copy); $('diagnostics').append(row);
  }
}
async function refresh(log = false, force = false) {
  if (refreshing || (busy && !force)) return;
  refreshing = true; controls();
  try {
    const previous = health.running;
    health = parseHealth(await invoke('session_health'));
    known = true;
    diagnostics();
    if (!errorSticky || log || health.running) {
      if (health.running) visual('running', 'Фильтрация включена', 'Движок работает, системный фильтр активен. Проверьте доступность нужного сервиса.');
      else if (health.session) visual('error', 'Нужна проверка', 'Сессия не подтверждена. Остановите её кнопкой восстановления и повторите запуск.');
      else if (available) visual('stopped', 'Готово к подключению', 'Выберите профиль и нажмите «Включить». Система запросит права администратора.');
    }
    if (previous && !health.running) event('Работа сессии прервана. Проверьте журнал движка.', 'error');
    if (log) event(health.running ? 'Проверка: фильтрация активна.' : health.session ? 'Обнаружена незавершённая сессия.' : 'Проверка: активной сессии нет.');
  } catch (error) {
    known = false;
    visual('error', 'Состояние неизвестно', friendlyError(error));
    diagnostics();
    if (log) event(friendlyError(error), 'error');
  } finally { refreshing = false; controls(); }
}
async function operate(stop = false) {
  if (busy || refreshing || !native) return false;
  busy = true; errorSticky = false; controls();
  visual('busy', stop ? 'Остановка…' : 'Подключение…', 'Подтвердите системный запрос администратора, если он появится.');
  let success = false;
  try {
    await invoke(stop ? 'session_stop' : 'session_start_default', stop ? {} : { profile: $('profile').value });
    await refresh(false, true);
    if (!known || (!stop && !health.running) || (stop && health.session)) throw new Error('Операция не подтверждена проверкой состояния. Сохраните отчёт и проверьте журнал.');
    event(stop ? 'Сессия остановлена, её сетевые ресурсы удалены.' : `Включён профиль «${$('profile').selectedOptions[0].text}».`, 'ok');
    success = true;
  } catch (error) {
    errorSticky = true;
    visual('error', 'Операция не завершена', friendlyError(error));
    event(friendlyError(error), 'error');
    await refresh(false, true);
  } finally { busy = false; controls(); }
  return success;
}
$('toggle').addEventListener('click', () => operate(health.session));
$('recover').addEventListener('click', () => operate(true));
$('refresh').addEventListener('click', () => { errorSticky = false; refresh(true); });
$('profile').addEventListener('change', () => {
  $('profile-description').textContent = descriptions[$('profile').value];
  try { localStorage.setItem('profile', $('profile').value); } catch { /* optional preference */ }
});
$('show-logs').addEventListener('click', async () => {
  try { $('engine-log').textContent = (await invoke('engine_logs')) || 'Движок ещё не записал сообщения.'; $('engine-log').hidden = false; }
  catch (error) { event(friendlyError(error), 'error'); }
});
$('export').addEventListener('click', async () => {
  $('export').disabled = true;
  try { const path = await invoke('export_report', { activity: $('activity').innerText }); event(`Отчёт сохранён: ${path}`, 'ok'); }
  catch (error) { event(friendlyError(error), 'error'); }
  finally { controls(); }
});
$('exit-cancel').addEventListener('click', () => $('exit-dialog').close());
$('exit-confirm').addEventListener('click', async () => {
  $('exit-dialog').close();
  if (await operate(true)) { clearInterval(timer); await invoke('quit_app'); }
});
async function requestClose() {
  if (busy || refreshing) { event('Дождитесь завершения операции перед выходом.'); return; }
  await refresh();
  if (known && !health.session) { clearInterval(timer); await invoke('quit_app'); }
  else if (!$('exit-dialog').open) $('exit-dialog').showModal();
}

async function init() {
  try {
    const saved = localStorage.getItem('profile');
    if (saved && descriptions[saved]) { $('profile').value = saved; $('profile-description').textContent = descriptions[saved]; }
  } catch { /* storage can be disabled */ }
  if (!native) {
    visual('stopped', 'Откройте desktop-приложение', 'В браузере доступен только просмотр интерфейса. Для управления сетью установите пакет для своей системы.');
    $('version').textContent = 'Предпросмотр'; diagnostics(); controls(); return;
  }
  event('Приложение запущено.');
  try {
    $('version').textContent = `v${await invoke('app_version')}`;
    const profile = await invoke('default_profile');
    available = profile.available;
    $('platform').textContent = { linux: 'Linux', windows: 'Windows', macos: 'macOS' }[profile.platform] ?? profile.platform;
    $('profile-state').textContent = available ? 'Встроенный' : 'Неполный пакет';
    $('profile-state').dataset.state = available ? 'ok' : 'error';
    $('runtime-state').textContent = available ? 'Установлены' : 'Не найдены';
    if (!available) visual('error', 'Пакет неполный', 'Установите полный desktop-пакет со встроенным движком.');
    await refresh();
    await listen('close-requested', requestClose);
    timer = setInterval(() => refresh(), 5000);
  } catch (error) { visual('error', 'Ошибка инициализации', friendlyError(error)); event(friendlyError(error), 'error'); }
  controls();
}
await init();
