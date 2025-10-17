require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const DATA_PATH = path.join(__dirname, 'data.json');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// In production, require a real JWT_SECRET
if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'dev_secret_change_me')) {
  console.error('FATAL: process.env.JWT_SECRET must be set in production');
  process.exit(1);
}

app.use(express.json());
// Serve a small demo UI to test the API in the browser
app.use(express.static(path.join(__dirname, 'public')));

function readData() {
  try {
    const raw = fs.readFileSync(DATA_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return { students: [], guardians: [] };
  }
}

function writeData(data) {
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
}

// Middleware to protect routes
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Register guardian: expects { rutStudent, email, password, name }
app.post('/register', (req, res) => {
  const { rutStudent, email, password, name } = req.body;
  if (!rutStudent || !email || !password || !name) {
    return res.status(400).json({ error: 'rutStudent, email, password and name are required' });
  }

  const data = readData();
  const student = data.students.find(s => s.rut === rutStudent);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  const existing = data.guardians.find(g => g.email === email);
  if (existing) return res.status(409).json({ error: 'Guardian already registered' });

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);

  const guardian = {
    id: Date.now().toString(),
    name,
    email,
    passwordHash: hash,
    studentRut: rutStudent,
    createdAt: new Date().toISOString()
  };

  data.guardians.push(guardian);
  writeData(data);

  res.status(201).json({ message: 'Guardian registered', guardianId: guardian.id });
});

// Login guardian: expects { email, password }
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const data = readData();
  const guardian = data.guardians.find(g => g.email === email);
  if (!guardian) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, guardian.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ guardianId: guardian.id, studentRut: guardian.studentRut, email: guardian.email }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// Get student academic info (protected)
app.get('/students/:rut/academic-info', authMiddleware, (req, res) => {
  const rut = req.params.rut;
  const data = readData();
  const guardian = data.guardians.find(g => g.id === req.user.guardianId);
  if (!guardian) return res.status(403).json({ error: 'Guardian not found' });
  if (guardian.studentRut !== rut) return res.status(403).json({ error: 'Not authorized to access this student' });

  const student = data.students.find(s => s.rut === rut);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  // Return only academic fields
  const academic = {
    rut: student.rut,
    name: student.name,
    course: student.course,
    grades: student.grades
  };
  res.json({ student: academic });
});

// NFC: Link a guardian and/or link a tag to a student
// POST /nfc/link
// Body options:
//  - { nfcUid, rutStudent, email, password, name } -> link tag to student and create guardian
//  - { nfcUid, rutStudent } -> just link tag to student (requires no auth)
app.post('/nfc/link', (req, res) => {
  const { nfcUid, rutStudent, email, password, name } = req.body;
  if (!nfcUid || !rutStudent) return res.status(400).json({ error: 'nfcUid and rutStudent are required' });

  const data = readData();
  const student = data.students.find(s => s.rut === rutStudent);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  // Link the tag to the student
  student.nfcUid = nfcUid;

  // Optionally create guardian linked to this student
  if (email || password || name) {
    if (!email || !password || !name) return res.status(400).json({ error: 'email, password and name are required to create guardian' });
    const existing = data.guardians.find(g => g.email === email);
    if (existing) return res.status(409).json({ error: 'Guardian already registered' });
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const guardian = {
      id: Date.now().toString(),
      name,
      email,
      passwordHash: hash,
      studentRut: rutStudent,
      createdAt: new Date().toISOString()
    };
    data.guardians.push(guardian);
  }

  writeData(data);
  res.json({ message: 'Linked NFC tag to student', nfcUid, studentRut: rutStudent });
});

// NFC: get student by tag UID (public by default). If you want it protected, wrap with authMiddleware.
app.get('/nfc/:uid/student', (req, res) => {
  const uid = req.params.uid;
  const data = readData();
  const student = data.students.find(s => s.nfcUid === uid);
  if (!student) return res.status(404).json({ error: 'Student not found for this UID' });
  const academic = {
    rut: student.rut,
    name: student.name,
    course: student.course,
    grades: student.grades
  };
  res.json({ student: academic });
});

// Simple health
app.get('/', (req, res) => res.send({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
