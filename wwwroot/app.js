const state = {
  rules: [],
  distros: [],
  status: null,
};

const notice = document.querySelector('#notice');
const log = document.querySelector('#log');
const rulesBody = document.querySelector('#rulesBody');
const distroSelect = document.querySelector('#distroSelect');
const wslIp = document.querySelector('#wslIp');
const loginCard = document.querySelector('#loginCard');
const accessUrls = document.querySelector('#accessUrls');
const toastHost = document.querySelector('#toastHost');

const api = async (url, options = {}) => {
  const response = await fetch(url, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    if (response.status === 401) {
      showLogin();
    }
    throw new Error(data?.error || `请求失败：${response.status}`);
  }

  return data;
};

const showToast = (message, type = 'success') => {
  if (!toastHost) {
    return;
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toastHost.append(toast);
  setTimeout(() => toast.remove(), 3600);
};

const setLog = (message, type = 'success') => {
  log.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  showToast(message, type);
};

const loadStatus = async () => {
  const status = await api('/api/status');
  state.status = status;
  if (status.authenticationEnabled && !status.authenticated) {
    showLogin();
  } else {
    hideLogin();
  }

  notice.className = `notice ${status.isAdministrator ? 'ok' : ''}`;
  const authText = status.authenticationEnabled ? '密码保护已启用。' : '未启用密码保护。';
  const externalText = status.externalAccessEnabled ? '外部访问已开启。' : '外部访问未开启。';
  notice.textContent = status.isAdministrator
    ? `已用管理员权限运行。监听地址：${status.listenUrl}。${externalText}${authText}${status.message}`
    : `当前不是管理员权限。监听地址：${status.listenUrl}。${externalText}${authText}查看通常可用，但新增/删除转发和防火墙规则可能失败。${status.message}`;
  renderAccessSettings(status);
};

const loadRules = async () => {
  state.rules = await api('/api/rules');
  renderRules();
};

const loadDistros = async () => {
  const result = await api('/api/wsl/distros');
  state.distros = result.distros || [];
  distroSelect.innerHTML = '';

  const wslForm = document.querySelector('#wslForm');
  const detectButton = document.querySelector('#detectWslIpBtn');
  const disabled = state.distros.length === 0;
  wslForm.querySelectorAll('input, select, button').forEach(element => {
    element.disabled = disabled;
  });
  detectButton.disabled = disabled;

  if (disabled) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = '未发现 WSL 发行版';
    distroSelect.append(option);
    wslIp.textContent = result.message || '未检测到 WSL，WSL 一键转发不可用。';
    return;
  }

  wslIp.textContent = '';
  for (const distro of state.distros) {
    const option = document.createElement('option');
    option.value = distro.name;
    option.textContent = distro.isDefault ? `${distro.name}（默认）` : distro.name;
    option.selected = distro.isDefault;
    distroSelect.append(option);
  }
};

const renderRules = () => {
  rulesBody.innerHTML = '';

  if (state.rules.length === 0) {
    rulesBody.innerHTML = '<tr><td colspan="6" class="empty">暂无转发规则</td></tr>';
    return;
  }

  for (const rule of state.rules) {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${escapeHtml(rule.listenAddress)}</td>
      <td>${rule.listenPort}</td>
      <td>${escapeHtml(rule.connectAddress)}</td>
      <td>${rule.connectPort}</td>
      <td>${escapeHtml(rule.source)}</td>
      <td></td>
    `;

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'danger';
    deleteBtn.textContent = '删除';
    deleteBtn.addEventListener('click', () => deleteRule(rule));
    row.lastElementChild.append(deleteBtn);
    rulesBody.append(row);
  }
};

const deleteRule = async (rule) => {
  if (!confirm(`删除 ${rule.listenAddress}:${rule.listenPort} 这条规则？`)) {
    return;
  }

  await api(`/api/rules?listenAddress=${encodeURIComponent(rule.listenAddress)}&listenPort=${rule.listenPort}`, {
    method: 'DELETE',
  });
  setLog('规则已删除');
  await loadRules();
};


const showLogin = () => {
  loginCard.hidden = false;
};

const hideLogin = () => {
  loginCard.hidden = true;
};


const renderAccessSettings = (status) => {
  const form = document.querySelector('#adminAccessForm');
  const externalAccessInput = form?.querySelector('input[name="externalAccessEnabled"]');
  if (externalAccessInput) {
    externalAccessInput.checked = Boolean(status.externalAccessEnabled);
  }

  const urls = status.accessUrls || [];
  if (accessUrls) {
    accessUrls.innerHTML = urls.length
      ? urls.map(item => `<span class="url-chip">${escapeHtml(item.name)}：${escapeHtml(item.url)}${item.isTailscale ? '（Tailscale）' : ''}</span>`).join(' ')
      : '未检测到可用外部地址';
  }

  const autoStartBtn = document.querySelector('#toggleAutoStartBtn');
  if (autoStartBtn) {
    autoStartBtn.textContent = status.autoStartEnabled ? '禁用开机自启' : '启用开机自启';
    autoStartBtn.dataset.enabled = String(Boolean(status.autoStartEnabled));
  }
};

const submitAdminAccess = async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const result = await api('/api/admin/access', {
    method: 'POST',
    body: JSON.stringify({
      externalAccessEnabled: form.get('externalAccessEnabled') === 'on',
      password: form.get('password')?.trim() || null,
    }),
  });
  const passwordInput = formElement.querySelector('input[name="password"]');
  if (passwordInput) {
    passwordInput.value = '';
  }
  setLog(result.message);
  await refreshAll();
};

const allowAdminFirewall = async () => {
  const result = await api('/api/admin/firewall/allow', { method: 'POST' });
  setLog(result.message);
};

const resetAdminConfig = async () => {
  if (!confirm('确定重置管理配置？这会关闭外部访问并清空管理密码。')) {
    return;
  }

  const result = await api('/api/admin/reset', { method: 'POST' });
  setLog(result.message);
  await refreshAll();
};

const toggleAutoStart = async () => {
  const button = document.querySelector('#toggleAutoStartBtn');
  const enabled = button?.dataset.enabled === 'true';
  const result = await api('/api/admin/autostart', {
    method: 'POST',
    body: JSON.stringify({ enabled: !enabled }),
  });
  setLog(result.message);
  await refreshAll();
};

const submitLogin = async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({ password: form.get('password') || '' }),
  });
  formElement.reset();
  hideLogin();
  setLog('登录成功');
  await refreshAll();
};

const submitRule = async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  await api('/api/rules', {
    method: 'POST',
    body: JSON.stringify({
      listenAddress: form.get('listenAddress')?.trim(),
      listenPort: Number(form.get('listenPort')),
      connectAddress: form.get('connectAddress')?.trim(),
      connectPort: Number(form.get('connectPort')),
    }),
  });
  setLog('普通端口转发已创建');
  await loadRules();
};

const submitWslForward = async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const result = await api('/api/wsl/forward', {
    method: 'POST',
    body: JSON.stringify({
      distro: form.get('distro') || null,
      listenPort: Number(form.get('listenPort')),
      targetPort: Number(form.get('targetPort')),
    }),
  });
  setLog(`${result.message}：${result.listenAddress}:${result.listenPort} -> ${result.connectAddress}:${result.connectPort}`);
  document.querySelector('#firewallForm input[name="port"]').value = result.listenPort;
  await loadRules();
};

const detectWslIp = async () => {
  const distro = distroSelect.value;
  const result = await api(`/api/wsl/ip?distro=${encodeURIComponent(distro)}`);
  wslIp.textContent = `当前 WSL IP：${result.ipAddress}`;
  setLog(`已探测 WSL IP：${result.ipAddress}`);
};

const submitFirewall = async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const result = await api('/api/firewall/allow', {
    method: 'POST',
    body: JSON.stringify({
      port: Number(form.get('port')),
      name: form.get('name')?.trim() || null,
    }),
  });
  setLog(result.message);
};

const refreshAll = async () => {
  try {
    await loadStatus();
    if (state.status?.authenticationEnabled && !state.status.authenticated) {
      setLog('请先登录');
      return;
    }

    await Promise.all([loadRules(), loadDistros()]);
    setLog('刷新完成');
  } catch (error) {
    setLog(error.message, 'error');
  }
};

const escapeHtml = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;');

const bind = () => {
  document.querySelector('#refreshBtn').addEventListener('click', refreshAll);
  document.querySelector('#loginForm').addEventListener('submit', wrapSubmit(submitLogin));
  document.querySelector('#adminAccessForm')?.addEventListener('submit', wrapSubmit(submitAdminAccess));
  document.querySelector('#allowAdminFirewallBtn')?.addEventListener('click', async () => {
    try {
      await allowAdminFirewall();
    } catch (error) {
      setLog(error.message, 'error');
    }
  });
  document.querySelector('#toggleAutoStartBtn')?.addEventListener('click', async () => {
    try {
      await toggleAutoStart();
    } catch (error) {
      setLog(error.message, 'error');
    }
  });
  document.querySelector('#resetAdminConfigBtn')?.addEventListener('click', async () => {
    try {
      await resetAdminConfig();
    } catch (error) {
      setLog(error.message, 'error');
    }
  });
  document.querySelector('#ruleForm').addEventListener('submit', wrapSubmit(submitRule));
  document.querySelector('#wslForm').addEventListener('submit', wrapSubmit(submitWslForward));
  document.querySelector('#firewallForm').addEventListener('submit', wrapSubmit(submitFirewall));
  document.querySelector('#detectWslIpBtn').addEventListener('click', async () => {
    try {
      await detectWslIp();
    } catch (error) {
      setLog(error.message, 'error');
    }
  });
};

const wrapSubmit = (handler) => async (event) => {
  try {
    await handler(event);
  } catch (error) {
    setLog(error.message, 'error');
  }
};

bind();
refreshAll();
