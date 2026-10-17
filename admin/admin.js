(function () {
'use strict';
function esc(t) {
  return String(t == null ? '' : t).replace(/[&<>"]/g, function (c) {
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
var root = el('root');
var tab = 'messages';

function show(html) { root.innerHTML = html; }

function boot() {
  api('/api/auth/session').then(function (d) {
    if (!d.authenticated) {
      show('<p>Sign in on the <a href="/">homepage</a> first, then come back.</p>');
      return;
    }
    var u = d.user;
    if (!u.is_admin) { show('<p>This account does not have administrator access.</p>'); return; }
    if (!u.totp_confirmed) { renderEnroll(); return; }
    if (u.aal !== 2) { renderMfa(); return; }
    renderDashboard();
  }).catch(function () {
    show('<p class="status err">Could not load. Try again.</p>');
  });
}

function renderEnroll() {
  show('<h2>Set up admin two-factor authentication</h2>' +
    '<p class="small">Add this secret to an authenticator app (it is shown once), then enter the 6-digit code it generates.</p>' +
    '<p><button type="button" class="action" id="gen">Generate my secret</button></p><div id="enrollbody"></div>');
  el('gen').addEventListener('click', function () {
    api('/api/auth/totp/enroll', 'POST', {}).then(function (d) {
      el('enrollbody').innerHTML = '<div class="secret">' + esc(d.secret) + '</div>' +
        '<p class="small">' + esc(d.otpauth_url) + '</p>' +
        '<label for="code">6-digit code</label><input class="field" id="code" inputmode="numeric" maxlength="6">' +
        '<button type="button" class="action" id="confirm">Confirm</button><p class="status" id="st"></p>';
      el('confirm').addEventListener('click', function () {
        api('/api/auth/totp/confirm', 'POST', { code: el('code').value })
          .then(function () { renderMfa(); })
          .catch(function (e) { el('st').textContent = e.message; el('st').className = 'status err'; });
      });
    }).catch(function (e) { el('enrollbody').innerHTML = '<p class="status err">' + esc(e.message) + '</p>'; });
  });
}

function renderMfa() {
  show('<h2>Admin verification</h2>' +
    '<label for="code">Authenticator code</label><input class="field" id="code" inputmode="numeric" maxlength="6">' +
    '<button type="button" class="action" id="go">Verify</button><p class="status" id="st"></p>');
  el('go').addEventListener('click', function () {
    api('/api/auth/totp/verify', 'POST', { code: el('code').value })
      .then(function () { renderDashboard(); })
      .catch(function (e) { el('st').textContent = e.message; el('st').className = 'status err'; });
  });
  el('code').addEventListener('keydown', function (ev) { if (ev.key === 'Enter') el('go').click(); });
}

function tabs() {
  return '<div class="tabs">' +
    ['messages', 'comments', 'users', 'outbox', 'audit'].map(function (t) {
      return '<button type="button" data-tab="' + t + '" class="' + (t === tab ? 'on' : '') + '">' + t.charAt(0).toUpperCase() + t.slice(1) + '</button>';
    }).join('') + '</div><div id="body"><p class="status">Loading...</p></div>';
}
function renderDashboard() {
  show(tabs());
  root.querySelectorAll('.tabs button').forEach(function (b) {
    b.addEventListener('click', function () { tab = b.getAttribute('data-tab'); renderDashboard(); });
  });
  if (tab === 'messages') loadMessages();
  else if (tab === 'comments') loadComments();
  else if (tab === 'users') loadUsers();
  else if (tab === 'outbox') loadOutbox();
  else if (tab === 'audit') loadAudit();
}

function loadMessages(q) {
  var url = '/api/admin/messages' + (q ? '?q=' + encodeURIComponent(q) : '');
  api(url).then(function (d) {
    var html = '<div class="searchrow"><input class="field" id="q" placeholder="Search subject, body, sender" value="' + esc(q || '') + '">' +
      '<button type="button" class="action" id="search">Search</button></div>';
    if (!d.messages.length) html += '<p class="small">No messages.</p>';
    d.messages.forEach(function (m) {
      html += '<div class="item"><div class="meta">' + esc(m.display_name) + ' &lt;' + esc(m.email || '') + '&gt; &middot; ' + esc(m.created_at) +
        ' &middot; ' + (m.from_admin ? 'reply sent' : esc(m.status)) + '</div>' +
        '<div><strong>' + esc(m.subject) + '</strong></div><div>' + esc(m.body) + '</div>' +
        (m.from_admin ? '' :
          '<div class="ops">' +
          ['unread', 'read', 'archived'].filter(function (s) { return s !== m.status; }).map(function (s) {
            return '<button type="button" class="linklike" data-op="' + s + '" data-id="' + esc(m.id) + '">Mark ' + s + '</button>';
          }).join('') +
          '<button type="button" class="linklike" data-op="reply" data-id="' + esc(m.id) + '">Reply</button>' +
          '<button type="button" class="linklike" data-op="del" data-id="' + esc(m.id) + '">Delete</button></div>' +
          '<div class="replybox" id="rb-' + esc(m.id) + '" hidden><textarea class="field" maxlength="5000"></textarea>' +
          '<button type="button" class="action" data-send="' + esc(m.id) + '">Send reply</button></div>') +
        '</div>';
    });
    el('body').innerHTML = html;
    el('search').addEventListener('click', function () { loadMessages(el('q').value.trim()); });
    root.querySelectorAll('button[data-op]').forEach(function (b) {
      b.addEventListener('click', function () {
        var op = b.getAttribute('data-op'), id = b.getAttribute('data-id');
        if (op === 'reply') { el('rb-' + id).hidden = !el('rb-' + id).hidden; return; }
        if (op === 'del') {
          api('/api/admin/messages/' + id, 'DELETE', {}).then(function () { loadMessages(q); }).catch(function () {});
        } else {
          api('/api/admin/messages/' + id, 'PATCH', { status: op }).then(function () { loadMessages(q); }).catch(function () {});
        }
      });
    });
    root.querySelectorAll('button[data-send]').forEach(function (b) {
      b.addEventListener('click', function () {
        var id = b.getAttribute('data-send');
        var ta = el('rb-' + id).querySelector('textarea');
        b.disabled = true;
        api('/api/admin/messages/' + id, 'POST', { body: ta.value })
          .then(function () { loadMessages(q); })
          .catch(function () { b.disabled = false; });
      });
    });
  }).catch(function (e) {
    el('body').innerHTML = '<p class="status err">' + esc(e.message) + '</p>';
    if (e.code === 'mfa_required') renderMfa();
  });
}

function loadComments() {
  api('/api/admin/comments').then(function (d) {
    var html = '';
    if (!d.comments.length) html += '<p class="small">No comments.</p>';
    d.comments.forEach(function (c) {
      html += '<div class="item"><div class="meta">' + esc(c.display_name) + ' &lt;' + esc(c.email || '') + '&gt; &middot; ' + esc(c.created_at) +
        (c.reports ? ' &middot; ' + c.reports + ' report(s)' : '') + (c.moderated ? ' &middot; hidden' : '') + (c.deleted_at ? ' &middot; deleted' : '') + '</div>' +
        '<div>' + esc(c.body) + '</div>' +
        '<div class="ops">' +
        (c.moderated ? '<button type="button" class="linklike" data-op="unmod" data-id="' + esc(c.id) + '">Unhide</button>'
                     : '<button type="button" class="linklike" data-op="mod" data-id="' + esc(c.id) + '">Hide</button>') +
        (c.deleted_at ? '' : '<button type="button" class="linklike" data-op="del" data-id="' + esc(c.id) + '">Delete</button>') +
        '</div></div>';
    });
    el('body').innerHTML = html;
    root.querySelectorAll('button[data-op]').forEach(function (b) {
      b.addEventListener('click', function () {
        var op = b.getAttribute('data-op'), id = b.getAttribute('data-id');
        var call = op === 'del'
          ? api('/api/admin/comments/' + id, 'DELETE', {})
          : api('/api/admin/comments/' + id, 'PATCH', { moderated: op === 'mod' });
        call.then(function () { loadComments(); }).catch(function () {});
      });
    });
  }).catch(function (e) { el('body').innerHTML = '<p class="status err">' + esc(e.message) + '</p>'; });
}

function loadUsers() {
  api('/api/admin/users').then(function (d) {
    var html = '';
    d.users.forEach(function (u) {
      html += '<div class="item"><div class="meta">' + esc(u.created_at) + (u.is_admin ? ' &middot; admin' : '') + '</div>' +
        '<div>' + esc(u.display_name) + ' &lt;' + esc(u.email || u.phone || '') + '&gt; &middot; ' +
        (u.email_verified || u.phone_verified ? 'verified' : 'unverified') + ' &middot; ' + esc(u.status) + '</div>' +
        '<div class="ops">' +
        (u.status === 'active'
          ? '<button type="button" class="linklike" data-op="suspended" data-id="' + esc(u.id) + '">Suspend</button>'
          : '<button type="button" class="linklike" data-op="active" data-id="' + esc(u.id) + '">Reactivate</button>') +
        '</div></div>';
    });
    el('body').innerHTML = html || '<p class="small">No users.</p>';
    root.querySelectorAll('button[data-op]').forEach(function (b) {
      b.addEventListener('click', function () {
        api('/api/admin/users/' + b.getAttribute('data-id'), 'PATCH', { status: b.getAttribute('data-op') })
          .then(function () { loadUsers(); }).catch(function () {});
      });
    });
  }).catch(function (e) { el('body').innerHTML = '<p class="status err">' + esc(e.message) + '</p>'; });
}

function loadOutbox() {
  api('/api/admin/outbox').then(function (d) {
    var html = '<p class="small">Undelivered mail (only used while no email provider is configured). Delivered items show a sent time.</p>';
    if (!d.outbox.length) html += '<p class="small">Empty.</p>';
    d.outbox.forEach(function (m) {
      html += '<div class="item"><div class="meta">' + esc(m.kind) + ' &rarr; ' + esc(m.to_email) + ' &middot; ' + esc(m.created_at) +
        (m.sent_at ? ' &middot; sent' : ' &middot; NOT delivered') + '</div>' +
        '<div><strong>' + esc(m.subject) + '</strong></div><div class="secret">' + esc(m.body) + '</div></div>';
    });
    el('body').innerHTML = html;
  }).catch(function (e) { el('body').innerHTML = '<p class="status err">' + esc(e.message) + '</p>'; });
}

function loadAudit() {
  api('/api/admin/audit').then(function (d) {
    var html = '';
    if (!d.audit.length) html += '<p class="small">No admin actions recorded yet.</p>';
    d.audit.forEach(function (a) {
      html += '<div class="item"><div class="meta">' + esc(a.created_at) + '</div>' +
        '<div>' + esc(a.actor || 'system') + ': ' + esc(a.action) + ' ' + esc(a.target_type) + ' ' + esc(a.target_id || '') + '</div></div>';
    });
    el('body').innerHTML = html;
  }).catch(function (e) { el('body').innerHTML = '<p class="status err">' + esc(e.message) + '</p>'; });
}

boot();
})();
