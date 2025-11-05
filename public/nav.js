// Abortable fetch helpers available ASAP (before DOMContentLoaded)
const __cc_controllers = new Set();
function __cc_abortAllFetches(){ __cc_controllers.forEach(c => { try { c.abort(); } catch {} }); __cc_controllers.clear(); }
window.abortableFetch = function(input, init = {}){
  const c = new AbortController();
  __cc_controllers.add(c);
  const merged = { ...init, signal: c.signal };
  if (!merged.credentials) merged.credentials = 'same-origin';
  return fetch(input, merged).finally(() => __cc_controllers.delete(c));
}
window.addEventListener('beforeunload', __cc_abortAllFetches);
window.addEventListener('pagehide', __cc_abortAllFetches);
document.addEventListener('visibilitychange', ()=>{ if (document.hidden) __cc_abortAllFetches(); });

document.addEventListener('DOMContentLoaded', async () => {
  const root = document.getElementById('navbar') || (() => { const d=document.createElement('div'); d.id='navbar'; document.body.prepend(d); return d; })();

  async function getUser() {
    try {
      const res = await abortableFetch('/api/v1/user', { credentials: 'same-origin' });
      if (!res.ok) return null;
      const data = await res.json();
      return data.user || null;
    } catch { return null; }
  }

  async function getUnread() {
    try {
      const res = await abortableFetch('/api/v1/notifications', { credentials: 'same-origin' });
      if (!res.ok) return 0;
      const data = await res.json();
      return (data.notifications || []).filter(n => !n.read).length;
    } catch { return 0; }
  }

  const user = await getUser();
  const unread = user ? await getUnread() : 0;
  // Detect if an admin exists to optionally show setup link
  let hasAdmin = true;
  try {
    const s = await abortableFetch('/api/v1/admin/state');
    if (s.ok) { const d = await s.json(); hasAdmin = !!d.hasAdmin; }
  } catch {}

  const icon = (paths) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5 transition-transform group-hover:scale-110">${paths}</svg>`;

  const ic = {
    // Cart brand
    brand: icon('<path d="M2.25 4.5h2.25l1.8 9.6A2.25 2.25 0 008.5 16.5h7.25a2.25 2.25 0 002.17-1.65l1.33-5.35H7.5"/><path d="M9 20.25a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zm9 0a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z"/>'),
    // Home (logged-out root)
    landing: icon('<path d="M2.25 12l9.75-7.5L21.75 12V20.25A1.5 1.5 0 0120.25 21.75H3.75A1.5 1.5 0 012.25 20.25V12z"/>'),
    // Dashboard (logged-in)
    home: icon('<path d="M3 3h8.25v8.25H3V3zm9.75 0H21v5.25h-8.25V3zM3 12.75h5.25V21H3v-8.25zm7.5 0H21V21h-10.5v-8.25z"/>'),
    requests: icon('<path d="M4.5 5.25h15a.75.75 0 01.75.75v12a.75.75 0 01-.75.75h-15a.75.75 0 01-.75-.75v-12a.75.75 0 01.75-.75zm2.25 3h10.5M6.75 12h10.5M6.75 15h6.75"/>'),
    chat: icon('<path d="M3 5.25A2.25 2.25 0 015.25 3h13.5A2.25 2.25 0 0121 5.25v7.5A2.25 2.25 0 0118.75 15H9l-4.5 4.5V15H5.25A2.25 2.25 0 013 12.75v-7.5z"/>'),
    bell: icon('<path d="M12 21a2.25 2.25 0 002.25-2.25h-4.5A2.25 2.25 0 0012 21zm6-6.75c0-3.728-2.03-6.866-5.25-7.59V5.25a.75.75 0 10-1.5 0v1.41C7.03 7.384 5 10.522 5 14.25H3.75a.75.75 0 000 1.5h16.5a.75.75 0 000-1.5H18z"/>'),
    admin: icon('<path d="M12 2.25l7.5 4.5v5.25c0 4.557-3.21 8.736-7.5 9.75-4.29-1.014-7.5-5.193-7.5-9.75V6.75l7.5-4.5z"/>'),
    logout: icon('<path d="M9 8.25V6.75A2.25 2.25 0 0111.25 4.5h6A2.25 2.25 0 0119.5 6.75v10.5A2.25 2.25 0 0117.25 19.5h-6A2.25 2.25 0 019 17.25V15.75M12 12h9m0 0l-3-3m3 3l-3 3"/>')
  };

  function link(href, label, iconSvg, extraRight = '') {
    return `<a href="${href}" class="inline-flex items-center gap-2 text-gray-700 hover:text-blue-600 px-3 py-1.5 rounded-lg hover:bg-blue-50 transition" title="${label}">${iconSvg}<span class="hidden sm:inline">${label}</span>${extraRight}</a>`;
  }

  const brandLink = user ? '/home' : '/';
  const brand = `<a href="${brandLink}" class="flex items-center gap-2 text-blue-700 font-semibold group">${ic.brand}<span>Campus Cart</span></a>`;

  let right = '';
  if (user) {
    const badge = unread > 0 ? `<span class="ml-1 inline-flex items-center justify-center text-xs font-bold text-white bg-red-600 rounded-full w-5 h-5">${unread}</span>` : '';
    right += link('/home', 'Dashboard', ic.home);
    right += link('/requests.html', 'Requests', ic.requests);
    right += link('/chat.html', 'Chat', ic.chat);
    right += link('/notifications.html', 'Notifications', ic.bell, badge);
  if (user.role === 'ADMIN') right += link('/admin.html', 'Admin', ic.admin);
  else if (!hasAdmin) right += link('/admin-setup.html', 'Admin setup', ic.admin);
    right += `<button id="nav-logout" class="inline-flex items-center gap-2 text-gray-700 hover:text-blue-600 px-3 py-1.5 rounded-lg hover:bg-blue-50 transition" title="Logout">${ic.logout}<span class="hidden sm:inline">Logout</span></button>`;
  } else {
    right += link('/', 'Home', ic.landing);
    right += link('/login', 'Login', ic.home);
    right += link('/signup', 'Sign up', ic.requests);
  }

  root.innerHTML = `
    <div class="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-gray-200 shadow-sm">
      <div class="max-w-5xl mx-auto flex items-center justify-between px-4 py-2">
        ${brand}
        <div class="flex items-center gap-1 sm:gap-2">${right}</div>
      </div>
    </div>`;

  const logoutBtn = document.getElementById('nav-logout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try { await abortableFetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch {}
      location.href = '/login';
    });
  }
});
