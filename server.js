const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const IDLE_LIMIT_MS = 15 * 60 * 1000; // 15 minutes

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const ATTENDANCE_FILE = path.join(DATA_DIR, 'attendance.json');
const LEAVE_FILE = path.join(DATA_DIR, 'leave_requests.json');
const BALANCES_FILE = path.join(DATA_DIR, 'leave_balances.json');

const COMPANY_START = '09:30:00'; // check-in after this counts as late
const STANDARD_WORK_MINUTES = 8 * 60; // work beyond this on a day counts as overtime

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Storage helpers ----------

function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  if (!fs.existsSync(USERS_FILE)) {
    const seed = [
      { id: 'u1', name: 'Karthik MD', email: 'md@ozone.co', password: bcrypt.hashSync('md123', 8), role: 'md', department: 'Leadership', managerId: null },
      { id: 'u2', name: 'Divya Manager', email: 'manager@ozone.co', password: bcrypt.hashSync('manager123', 8), role: 'manager', department: 'Engineering', managerId: null },
      { id: 'u3', name: 'Asha Menon', email: 'asha@ozone.co', password: bcrypt.hashSync('emp123', 8), role: 'employee', department: 'Engineering', managerId: 'u2' },
      { id: 'u4', name: 'Rahul Verma', email: 'rahul@ozone.co', password: bcrypt.hashSync('emp123', 8), role: 'employee', department: 'Engineering', managerId: 'u2' }
    ];
    fs.writeFileSync(USERS_FILE, JSON.stringify(seed, null, 2));
  }
  if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, JSON.stringify({}, null, 2));
  if (!fs.existsSync(ATTENDANCE_FILE)) fs.writeFileSync(ATTENDANCE_FILE, JSON.stringify([], null, 2));
  if (!fs.existsSync(LEAVE_FILE)) fs.writeFileSync(LEAVE_FILE, JSON.stringify([], null, 2));
  if (!fs.existsSync(BALANCES_FILE)) {
    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    const balances = {};
    users.forEach(u => { balances[u.id] = { sick: 6, casual: 8, earned: 10 }; });
    fs.writeFileSync(BALANCES_FILE, JSON.stringify(balances, null, 2));
  }
}

function readJSON(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

function todayStr(d = new Date()) { return d.toISOString().slice(0, 10); }
function timeStr(d = new Date()) { return d.toTimeString().slice(0, 8); }
function genId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

function toMinutes(hhmmss) {
  const [h, m] = hhmmss.split(':').map(Number);
  return h * 60 + m;
}
function minutesBetween(start, end) {
  let mins = toMinutes(end) - toMinutes(start);
  if (mins < 0) mins += 24 * 60;
  return mins;
}
function totalWorkMinutes(record) {
  return record.segments
    .filter(s => s.type === 'work' && s.end)
    .reduce((sum, s) => sum + minutesBetween(s.start, s.end), 0);
}
function daysBetween(startDate, endDate) {
  const start = new Date(startDate);
  const end = new Date(endDate);
  const diff = Math.round((end - start) / 86400000);
  return diff >= 0 ? diff + 1 : 0;
}

ensureDataFiles();

// ---------- Auth ----------

function createSession(userId) {
  const sessions = readJSON(SESSIONS_FILE);
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = { userId, createdAt: Date.now() };
  writeJSON(SESSIONS_FILE, sessions);
  return token;
}

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  const sessions = readJSON(SESSIONS_FILE);
  const session = sessions[token];
  if (!session) return res.status(401).json({ error: 'Session expired. Please log in again.' });
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === session.userId);
  if (!user) return res.status(401).json({ error: 'User not found.' });
  req.user = user;
  req.token = token;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed for your role.' });
    next();
  };
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, department: u.department, managerId: u.managerId };
}

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
  if (!user || !bcrypt.compareSync(password || '', user.password)) {
    return res.status(400).json({ error: 'Invalid email or password.' });
  }
  const token = createSession(user.id);
  res.json({ token, user: publicUser(user) });
});

app.post('/api/logout', auth, (req, res) => {
  const sessions = readJSON(SESSIONS_FILE);
  delete sessions[req.token];
  writeJSON(SESSIONS_FILE, sessions);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json(publicUser(req.user));
});

// ---------- Attendance state helpers ----------
//
// One attendance record per user per day.
// status: 'checked_out' | 'working' | 'on_break' | 'lunch' | 'auto_checked_out'
// segments: [{ type: 'work'|'break'|'lunch', start, end }]
// workNote: free-text "what I'm currently doing"

function getTodayRecord(userId, create) {
  const records = readJSON(ATTENDANCE_FILE);
  const today = todayStr();
  let record = records.find(r => r.userId === userId && r.date === today);
  if (!record && create) {
    record = {
      id: genId(),
      userId,
      date: today,
      checkIn: null,
      checkOut: null,
      status: 'checked_out',
      workNote: '',
      segments: [],
      lastActivity: Date.now(),
      autoCheckedOut: false,
      isLate: false,
      overtimeMinutes: 0
    };
    records.push(record);
    writeJSON(ATTENDANCE_FILE, records);
  }
  return { records, record };
}

function saveRecord(records, record) {
  const idx = records.findIndex(r => r.id === record.id);
  records[idx] = record;
  writeJSON(ATTENDANCE_FILE, records);
}

function closeOpenSegment(record, endTime) {
  const open = record.segments.find(s => !s.end);
  if (open) open.end = endTime;
}

// Auto-checkout sweep: closes anyone idle past IDLE_LIMIT_MS.
// Runs before any attendance read/write so state is always fresh.
function sweepIdleUsers() {
  const records = readJSON(ATTENDANCE_FILE);
  const now = Date.now();
  let changed = false;
  records.forEach(r => {
    if (r.status !== 'checked_out' && r.status !== 'auto_checked_out') {
      if (now - r.lastActivity > IDLE_LIMIT_MS) {
        const t = timeStr(new Date(r.lastActivity + IDLE_LIMIT_MS));
        closeOpenSegment(r, t);
        r.checkOut = t;
        r.status = 'auto_checked_out';
        r.autoCheckedOut = true;
        r.workNote = 'Auto checked out (inactive 15+ min)';
        r.overtimeMinutes = Math.max(totalWorkMinutes(r) - STANDARD_WORK_MINUTES, 0);
        changed = true;
      }
    }
  });
  if (changed) writeJSON(ATTENDANCE_FILE, records);
}

function touch(record) {
  record.lastActivity = Date.now();
}

// ---------- Attendance routes ----------

app.get('/api/attendance/today', auth, (req, res) => {
  sweepIdleUsers();
  const { record } = getTodayRecord(req.user.id, true);
  res.json(record);
});

app.post('/api/attendance/checkin', auth, (req, res) => {
  sweepIdleUsers();
  const { records, record } = getTodayRecord(req.user.id, true);
  if (record.status !== 'checked_out') {
    return res.status(409).json({ error: 'Already checked in.' });
  }
  const now = timeStr();
  if (!record.checkIn) {
    record.checkIn = now;
    record.isLate = toMinutes(now) > toMinutes(COMPANY_START);
  }
  record.checkOut = null;
  record.status = 'working';
  record.workNote = (req.body && req.body.workNote) || record.workNote || 'Starting work';
  record.segments.push({ type: 'work', start: now, end: null });
  touch(record);
  saveRecord(records, record);
  res.json(record);
});

app.post('/api/attendance/checkout', auth, (req, res) => {
  sweepIdleUsers();
  const { records, record } = getTodayRecord(req.user.id, true);
  if (record.status === 'checked_out' || record.status === 'auto_checked_out') {
    return res.status(409).json({ error: 'Not currently checked in.' });
  }
  const now = timeStr();
  closeOpenSegment(record, now);
  record.checkOut = now;
  record.status = 'checked_out';
  record.workNote = '';
  const worked = totalWorkMinutes(record);
  record.overtimeMinutes = Math.max(worked - STANDARD_WORK_MINUTES, 0);
  touch(record);
  saveRecord(records, record);
  res.json(record);
});

app.post('/api/attendance/break/start', auth, (req, res) => {
  sweepIdleUsers();
  const { records, record } = getTodayRecord(req.user.id, true);
  if (record.status !== 'working') {
    return res.status(409).json({ error: 'You need to be checked in and working to start a break.' });
  }
  const type = req.body && req.body.type === 'lunch' ? 'lunch' : 'break';
  const now = timeStr();
  closeOpenSegment(record, now);
  record.status = type;
  record.workNote = type === 'lunch' ? 'On lunch break' : 'On break';
  record.segments.push({ type, start: now, end: null });
  touch(record);
  saveRecord(records, record);
  res.json(record);
});

app.post('/api/attendance/break/end', auth, (req, res) => {
  sweepIdleUsers();
  const { records, record } = getTodayRecord(req.user.id, true);
  if (record.status !== 'break' && record.status !== 'lunch') {
    return res.status(409).json({ error: 'You are not currently on a break.' });
  }
  const now = timeStr();
  closeOpenSegment(record, now);
  record.status = 'working';
  record.workNote = 'Back to work';
  record.segments.push({ type: 'work', start: now, end: null });
  touch(record);
  saveRecord(records, record);
  res.json(record);
});

app.post('/api/attendance/note', auth, (req, res) => {
  sweepIdleUsers();
  const { records, record } = getTodayRecord(req.user.id, true);
  if (record.status !== 'working') {
    return res.status(409).json({ error: 'You can only update your work note while actively working.' });
  }
  record.workNote = (req.body && req.body.workNote) || '';
  touch(record);
  saveRecord(records, record);
  res.json(record);
});

// Frontend calls this periodically (heartbeat) while the tab is open and
// the user is active, so idle time is measured from real inactivity.
app.post('/api/attendance/ping', auth, (req, res) => {
  sweepIdleUsers();
  const { records, record } = getTodayRecord(req.user.id, true);
  if (record.status === 'working' || record.status === 'break' || record.status === 'lunch') {
    touch(record);
    saveRecord(records, record);
  }
  res.json({ status: record.status });
});

// ---------- Team visibility ----------
// Manager: sees their direct reports. MD: sees everyone.

app.get('/api/team/status', auth, requireRole('manager', 'md'), (req, res) => {
  sweepIdleUsers();
  const users = readJSON(USERS_FILE);
  const records = readJSON(ATTENDANCE_FILE);
  const today = todayStr();

  const visibleUsers = req.user.role === 'md'
    ? users.filter(u => u.id !== req.user.id)
    : users.filter(u => u.managerId === req.user.id);

  const result = visibleUsers.map(u => {
    const record = records.find(r => r.userId === u.id && r.date === today);
    return {
      id: u.id,
      name: u.name,
      department: u.department,
      role: u.role,
      status: record ? record.status : 'checked_out',
      workNote: record ? record.workNote : '',
      checkIn: record ? record.checkIn : null,
      checkOut: record ? record.checkOut : null,
      autoCheckedOut: record ? record.autoCheckedOut : false
    };
  });

  res.json(result);
});

// ---------- Scope helper ----------
// Which user IDs a manager/MD is allowed to see.

function visibleUserIds(actingUser, users) {
  if (actingUser.role === 'md') return users.map(u => u.id);
  if (actingUser.role === 'manager') {
    return users.filter(u => u.managerId === actingUser.id).map(u => u.id);
  }
  return [actingUser.id];
}

// ---------- Leave: employee-facing ----------

app.get('/api/leave/balance', auth, (req, res) => {
  const balances = readJSON(BALANCES_FILE);
  res.json(balances[req.user.id] || { sick: 0, casual: 0, earned: 0 });
});

app.get('/api/leave/my', auth, (req, res) => {
  const requests = readJSON(LEAVE_FILE);
  const mine = requests
    .filter(r => r.userId === req.user.id)
    .sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : -1));
  res.json(mine);
});

app.post('/api/leave/request', auth, (req, res) => {
  const { type, startDate, endDate, reason } = req.body || {};
  if (!type || !startDate || !endDate) {
    return res.status(400).json({ error: 'Leave type, start date, and end date are required.' });
  }
  if (!['sick', 'casual', 'earned'].includes(type)) {
    return res.status(400).json({ error: 'Leave type must be sick, casual, or earned.' });
  }
  const days = daysBetween(startDate, endDate);
  if (days <= 0) {
    return res.status(400).json({ error: 'End date must be on or after the start date.' });
  }

  const balances = readJSON(BALANCES_FILE);
  const bal = balances[req.user.id] || { sick: 0, casual: 0, earned: 0 };
  if (days > bal[type]) {
    return res.status(400).json({ error: `Not enough ${type} leave balance. You have ${bal[type]} day(s) left, requested ${days}.` });
  }

  const requests = readJSON(LEAVE_FILE);
  const request = {
    id: genId(),
    userId: req.user.id,
    userName: req.user.name,
    type,
    startDate,
    endDate,
    days,
    reason: reason || '',
    status: 'pending',
    requestedAt: new Date().toISOString(),
    decidedBy: null,
    decidedAt: null
  };
  requests.push(request);
  writeJSON(LEAVE_FILE, requests);
  res.status(201).json(request);
});

// ---------- Leave: manager/MD approvals ----------

app.get('/api/leave/team', auth, requireRole('manager', 'md'), (req, res) => {
  const users = readJSON(USERS_FILE);
  const allowedIds = visibleUserIds(req.user, users);
  const requests = readJSON(LEAVE_FILE)
    .filter(r => allowedIds.includes(r.userId))
    .sort((a, b) => (a.requestedAt < b.requestedAt ? 1 : -1));
  res.json(requests);
});

function decideLeave(req, res, decision) {
  const users = readJSON(USERS_FILE);
  const allowedIds = visibleUserIds(req.user, users);
  const requests = readJSON(LEAVE_FILE);
  const request = requests.find(r => r.id === req.params.id);
  if (!request) return res.status(404).json({ error: 'Leave request not found.' });
  if (!allowedIds.includes(request.userId)) return res.status(403).json({ error: 'Not allowed to decide on this request.' });
  if (request.status !== 'pending') return res.status(409).json({ error: `Already ${request.status}.` });

  request.status = decision;
  request.decidedBy = req.user.name;
  request.decidedAt = new Date().toISOString();
  writeJSON(LEAVE_FILE, requests);

  if (decision === 'approved') {
    const balances = readJSON(BALANCES_FILE);
    if (!balances[request.userId]) balances[request.userId] = { sick: 0, casual: 0, earned: 0 };
    balances[request.userId][request.type] = Math.max(balances[request.userId][request.type] - request.days, 0);
    writeJSON(BALANCES_FILE, balances);
  }

  res.json(request);
}

app.post('/api/leave/:id/approve', auth, requireRole('manager', 'md'), (req, res) => decideLeave(req, res, 'approved'));
app.post('/api/leave/:id/reject', auth, requireRole('manager', 'md'), (req, res) => decideLeave(req, res, 'rejected'));

// ---------- Late logs & overtime (manager/MD) ----------

app.get('/api/reports/late', auth, requireRole('manager', 'md'), (req, res) => {
  const users = readJSON(USERS_FILE);
  const allowedIds = visibleUserIds(req.user, users);
  const records = readJSON(ATTENDANCE_FILE)
    .filter(r => allowedIds.includes(r.userId) && r.isLate)
    .sort((a, b) => (a.date < b.date ? 1 : -1));
  const withNames = records.map(r => ({
    ...r,
    userName: (users.find(u => u.id === r.userId) || {}).name || 'Unknown'
  }));
  res.json(withNames);
});

app.get('/api/reports/overtime', auth, requireRole('manager', 'md'), (req, res) => {
  const users = readJSON(USERS_FILE);
  const allowedIds = visibleUserIds(req.user, users);
  const records = readJSON(ATTENDANCE_FILE)
    .filter(r => allowedIds.includes(r.userId) && r.overtimeMinutes > 0)
    .sort((a, b) => (a.date < b.date ? 1 : -1));
  const withNames = records.map(r => ({
    ...r,
    userName: (users.find(u => u.id === r.userId) || {}).name || 'Unknown'
  }));
  res.json(withNames);
});

app.listen(PORT, () => {
  console.log(`Ozone Attendance running at http://localhost:${PORT}`);
  console.log(`Seed logins: md@ozone.co / md123, manager@ozone.co / manager123, asha@ozone.co / emp123`);
});
