(function () {
'use strict';

function esc(t) {
  return String(t).replace(/[&<>"]/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  });
}
function el(id) { return document.getElementById(id); }
function api(path, method, body) {
  var opts = { method: method || 'GET', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-Requested-With'] = 'fetch';
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (r) {
    return r.json().catch(function () { return {}; }).then(function (d) {
      if (!r.ok) { var e = new Error(d.error || 'request failed'); e.code = d.code; e.status = r.status; throw e; }
      return d;
    });
  });
}
function ago(iso) {
  var t = new Date(iso + (iso && iso.indexOf('Z') === -1 ? 'Z' : ''));
  var s = Math.max(0, (Date.now() - t.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return t.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

// ---- theme: dark is the default for first-time visitors ----
var root = document.documentElement, themeBtn = el('theme');
function savedTheme() { try { return localStorage.getItem('theme'); } catch (e) { return null; } }
var saved = savedTheme();
root.setAttribute('data-theme', saved || 'dark');
function themeLabel() { themeBtn.textContent = root.getAttribute('data-theme') === 'dark' ? 'Light' : 'Dark'; }
themeLabel();
themeBtn.addEventListener('click', function () {
  var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('theme', next); } catch (e) {}
  themeLabel();
});

// ---- visitor counter (existing behavior preserved: read-only GET, then a
// qualified-view beacon after 5 visible seconds) ----
api('/api/views').then(function (d) {
  if (typeof d.views === 'number') el('views').textContent = d.views + ' visits';
}).catch(function () {});
var vseen = 0, vsent = false;
var vt = setInterval(function () {
  if (document.visibilityState !== 'visible') return;
  vseen += 1;
  if (vseen >= 5 && !vsent) {
    vsent = true; clearInterval(vt);
    try { navigator.sendBeacon('/api/views', new Blob([JSON.stringify({ t: vseen })], { type: 'application/json' })); } catch (e) {}
  } else if (vseen >= 6) { clearInterval(vt); }
}, 1000);

// ---- session state ----
var me = null, providers = { email: true, google: false, phone: false };
api('/api/auth/providers').then(function (d) { providers = d; }).catch(function () {});
function refreshSession() {
  return api('/api/auth/session').then(function (d) {
    me = d.authenticated ? d.user : null;
    renderAccount();
    renderCommentForm();
    return me;
  }).catch(function () { me = null; renderAccount(); renderCommentForm(); });
}

function renderAccount() {
  var area = el('accountarea');
  if (!me) {
    area.innerHTML = '<button type="button" id="signinbtn">Sign in</button>';
    el('signinbtn').addEventListener('click', function () { showAuth('signin'); });
    return;
  }
  area.innerHTML = '<div class="account"><button type="button" id="acctbtn">' + esc(me.display_name) + '</button>' +
    '<div class="accountmenu" id="acctmenu" hidden>' +
    '<div class="who">' + esc(me.email || '') + (me.email_verified ? '' : ' (unverified)') + '</div>' +
    (me.is_admin ? '<a href="/admin">Admin</a>' : '') +
    '<button type="button" id="signoutbtn">Sign out</button>' +
    '</div></div>';
  var menu = el('acctmenu');
  el('acctbtn').addEventListener('click', function () { menu.hidden = !menu.hidden; });
  el('signoutbtn').addEventListener('click', function () {
    api('/api/auth/logout', 'POST', {}).then(function () { return refreshSession(); }).then(function () {
      el('msgpanel').hidden = true;
    });
  });
}

// ---- auth panel ----
var authPanel = el('authpanel'), authBody = el('authbody'), authTitle = el('authtitle');
function showAuth(mode) {
  authPanel.hidden = false;
  renderAuth(mode);
  authPanel.scrollIntoView({ block: 'nearest' });
}
function hideAuth() { authPanel.hidden = true; }
function fieldHtml(id, label, type, autocomplete) {
  return '<label for="' + id + '">' + label + '</label><input class="field" id="' + id + '" type="' + type + '" autocomplete="' + autocomplete + '">';
}
function renderAuth(mode, notice) {
  var html = '';
  if (notice) html += '<p class="status">' + esc(notice) + '</p>';
  if (mode === 'signin') {
    authTitle.textContent = 'Sign in';
    html += fieldHtml('a_email', 'Email', 'email', 'email') +
      fieldHtml('a_pw', 'Password', 'password', 'current-password') +
      '<p><button type="button" class="action" id="a_go">Sign in</button></p>' +
      '<p class="status" id="a_status"></p>' +
      '<p class="small"><button type="button" class="linklike" id="a_forgot">Forgot password</button> &middot; <button type="button" class="linklike" id="a_register">Create an account</button></p>';
    if (providers.google) html += '<p><button type="button" class="action" id="a_google">Continue with Google</button></p>';
  } else if (mode === 'register') {
    authTitle.textContent = 'Create an account';
    html += fieldHtml('a_name', 'Display name', 'text', 'nickname') +
      fieldHtml('a_email', 'Email', 'email', 'email') +
      fieldHtml('a_pw', 'Password (10+ characters)', 'password', 'new-password') +
      '<p><button type="button" class="action" id="a_go">Create account</button></p>' +
      '<p class="status" id="a_status"></p>' +
      '<p class="small"><button type="button" class="linklike" id="a_signin">Back to sign in</button></p>';
  } else if (mode === 'forgot') {
    authTitle.textContent = 'Reset password';
    html += fieldHtml('a_email', 'Email', 'email', 'email') +
      '<p><button type="button" class="action" id="a_go">Send reset link</button></p>' +
      '<p class="status" id="a_status"></p>' +
      '<p class="small"><button type="button" class="linklike" id="a_signin">Back to sign in</button></p>';
  } else if (mode === 'reset') {
    authTitle.textContent = 'Choose a new password';
    html += fieldHtml('a_pw', 'New password (10+ characters)', 'password', 'new-password') +
      '<p><button type="button" class="action" id="a_go">Set new password</button></p>' +
      '<p class="status" id="a_status"></p>';
  }
  authBody.innerHTML = html;
  var statusEl = el('a_status');
  function fail(e) { statusEl.textContent = e.message || 'Something went wrong.'; statusEl.className = 'status err'; }
  if (el('a_signin')) el('a_signin').addEventListener('click', function () { renderAuth('signin'); });
  if (el('a_register')) el('a_register').addEventListener('click', function () { renderAuth('register'); });
  if (el('a_forgot')) el('a_forgot').addEventListener('click', function () { renderAuth('forgot'); });
  if (el('a_google')) el('a_google').addEventListener('click', function () { window.location.href = '/api/auth/google'; });
  el('a_go').addEventListener('click', function () {
    var btn = el('a_go'); btn.disabled = true;
    if (mode === 'signin') {
      api('/api/auth/login', 'POST', { email: el('a_email').value, password: el('a_pw').value })
        .then(function () { return refreshSession(); })
        .then(function () { hideAuth(); afterAuth(); })
        .catch(function (e) { btn.disabled = false; fail(e); });
    } else if (mode === 'register') {
      api('/api/auth/register', 'POST', { display_name: el('a_name').value, email: el('a_email').value, password: el('a_pw').value })
        .then(function (d) {
          return refreshSession().then(function () {
            hideAuth(); afterAuth();
            if (d.verification_required) alertInline('Account created. Check your email for a verification link before posting or messaging.');
          });
        })
        .catch(function (e) { btn.disabled = false; fail(e); });
    } else if (mode === 'forgot') {
      api('/api/auth/request-reset', 'POST', { email: el('a_email').value })
        .then(function () { renderAuth('signin', 'If that address has an account, a reset link is on its way.'); })
        .catch(function (e) { btn.disabled = false; fail(e); });
    } else if (mode === 'reset') {
      api('/api/auth/reset-password', 'POST', { token: resetToken, password: el('a_pw').value })
        .then(function () { resetToken = null; renderAuth('signin', 'Password changed. Sign in with the new password.'); })
        .catch(function (e) { btn.disabled = false; fail(e); });
    }
  });
}
function alertInline(msg) {
  var s = document.createElement('p');
  s.className = 'status';
  s.textContent = msg;
  authPanel.hidden = false;
  authTitle.textContent = 'Account';
  authBody.innerHTML = '';
  authBody.appendChild(s);
}

// ---- private messages ----
var msgPanel = el('msgpanel'), msgFab = el('msgfab'), msgOpen = false;
msgFab.addEventListener('click', function () {
  msgOpen = !msgOpen;
  msgPanel.hidden = !msgOpen;
  if (msgOpen) renderMessages();
});
function afterAuth() { if (msgOpen) renderMessages(); }
function renderMessages() {
  if (!me) {
    msgPanel.innerHTML = '<p class="small">Sign in to send a private message to ErenLabs.</p>' +
      '<p><button type="button" class="action" id="m_signin">Sign in</button></p>';
    el('m_signin').addEventListener('click', function () { showAuth('signin'); });
    return;
  }
  msgPanel.innerHTML = '<p class="status">Loading...</p>';
  api('/api/messages').then(function (d) {
    var html = '<h2 style="font-family:-apple-system,sans-serif;font-size:0.78rem;letter-spacing:0.08em;text-transform:uppercase;color:var(--muted);margin-bottom:10px">Messages</h2>';
    if (!d.messages.length) html += '<p class="small">No messages yet.</p>';
    d.messages.forEach(function (m) {
      html += '<div class="msg"><div class="meta">' + (m.from_admin ? 'ErenLabs' : 'You') + ' &middot; ' + esc(ago(m.created_at)) + '</div>' +
        '<div><strong>' + esc(m.subject) + '</strong></div><div>' + esc(m.body) + '</div></div>';
    });
    html += '<div style="margin-top:12px">' +
      '<label for="m_subject">Subject</label><input class="field" id="m_subject" maxlength="120">' +
      '<label for="m_body">Message</label><textarea class="field" id="m_body" maxlength="5000"></textarea>' +
      '<button type="button" class="action" id="m_send">Send</button>' +
      '<p class="status" id="m_status"></p></div>';
    msgPanel.innerHTML = html;
    msgPanel.scrollTop = 0;
    el('m_send').addEventListener('click', function () {
      var btn = el('m_send'); btn.disabled = true;
      el('m_status').textContent = 'Sending...';
      api('/api/messages', 'POST', { subject: el('m_subject').value, body: el('m_body').value })
        .then(function () { renderMessages(); })
        .catch(function (e) {
          btn.disabled = false;
          el('m_status').textContent = e.code === 'unverified' ? 'Verify your email address first.' : (e.message || 'Could not send.');
          el('m_status').className = 'status err';
        });
    });
  }).catch(function () {
    msgPanel.innerHTML = '<p class="status err">Could not load messages.</p>';
  });
}

// ---- discussion ----
var commentsPanel = el('commentspanel'), commentsToggle = el('commentstoggle');
var cursor = null, commentsLoaded = false;
commentsToggle.addEventListener('click', function () {
  commentsPanel.hidden = !commentsPanel.hidden;
  commentsToggle.setAttribute('aria-expanded', String(!commentsPanel.hidden));
  if (!commentsPanel.hidden && !commentsLoaded) { commentsLoaded = true; loadComments(); }
});
function loadComments() {
  var url = '/api/comments?limit=20' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
  api(url).then(function (d) {
    var list = el('commentslist');
    if (!cursor) list.innerHTML = '';
    if (!d.comments.length && !cursor) {
      list.innerHTML = '<p class="small">Nothing here yet.</p>';
    }
    d.comments.forEach(function (c) {
      var div = document.createElement('div');
      div.className = 'comment';
      var ops = '';
      if (c.own) ops = '<button type="button" class="linklike" data-op="edit" data-id="' + esc(c.id) + '">Edit</button>' +
        '<button type="button" class="linklike" data-op="del" data-id="' + esc(c.id) + '">Delete</button>';
      else if (me) ops = '<button type="button" class="linklike" data-op="report" data-id="' + esc(c.id) + '">Report</button>';
      div.innerHTML = '<div class="meta">' + esc(c.display_name) + ' &middot; ' + esc(ago(c.created_at)) + (c.edited_at ? ' &middot; edited' : '') + '</div>' +
        '<div class="cbody">' + esc(c.body) + '</div>' +
        (ops ? '<div class="ops">' + ops + '</div>' : '');
      list.appendChild(div);
    });
    cursor = d.next_cursor;
    el('commentsmore').hidden = !cursor;
  }).catch(function () {
    if (!cursor) el('commentslist').innerHTML = '<p class="status err">Discussion is unavailable right now.</p>';
  });
}
el('loadmore').addEventListener('click', loadComments);
el('commentslist').addEventListener('click', function (ev) {
  var b = ev.target.closest ? ev.target.closest('button[data-op]') : null;
  if (!b) return;
  var id = b.getAttribute('data-id'), op = b.getAttribute('data-op');
  if (op === 'del') {
    api('/api/comments/' + encodeURIComponent(id), 'DELETE', {}).then(function () {
      cursor = null; commentsLoaded = true; loadComments();
    }).catch(function () {});
  } else if (op === 'edit') {
    var bodyEl = b.closest('.comment').querySelector('.cbody');
    var current = bodyEl.textContent;
    bodyEl.innerHTML = '<textarea class="field" maxlength="1000"></textarea><button type="button" class="action">Save</button>';
    var ta = bodyEl.querySelector('textarea'); ta.value = current;
    bodyEl.querySelector('button').addEventListener('click', function () {
      api('/api/comments/' + encodeURIComponent(id), 'PATCH', { body: ta.value }).then(function () {
        cursor = null; loadComments();
      }).catch(function () { cursor = null; loadComments(); });
    });
  } else if (op === 'report') {
    api('/api/comments/' + encodeURIComponent(id) + '/report', 'POST', { reason: 'inappropriate' })
      .then(function () { b.textContent = 'Reported'; b.disabled = true; })
      .catch(function () { b.textContent = 'Reported'; b.disabled = true; });
  }
});
function renderCommentForm() {
  var box = el('commentform');
  if (!me) {
    box.innerHTML = '<p class="small"><button type="button" class="linklike" id="c_signin">Sign in</button> to join the discussion.</p>';
    el('c_signin').addEventListener('click', function () { showAuth('signin'); });
    return;
  }
  box.innerHTML = '<label for="c_body">Add a comment as ' + esc(me.display_name) + '</label>' +
    '<textarea class="field" id="c_body" maxlength="1000"></textarea>' +
    '<button type="button" class="action" id="c_post">Post</button>' +
    '<p class="status" id="c_status"></p>';
  el('c_post').addEventListener('click', function () {
    var btn = el('c_post'); btn.disabled = true;
    api('/api/comments', 'POST', { body: el('c_body').value }).then(function () {
      el('c_body').value = ''; btn.disabled = false;
      cursor = null; loadComments();
    }).catch(function (e) {
      btn.disabled = false;
      el('c_status').textContent = e.code === 'unverified' ? 'Verify your email address first.' : (e.message || 'Could not post.');
      el('c_status').className = 'status err';
    });
  });
}

// ---- URL parameters from email links ----
var params = new URLSearchParams(window.location.search);
var resetToken = params.get('reset');
if (params.get('verified')) { history.replaceState(null, '', '/'); alertInline('Email verified. You can now post and send messages.'); }
if (params.get('signedin')) { history.replaceState(null, '', '/'); }
if (resetToken) { history.replaceState(null, '', '/'); showAuth('reset'); }

refreshSession();
})();
