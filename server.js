const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();
const pool = require('./db');

const app = express();

// app.use(cors());

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://yourstaffing.online',
  'https://www.yourstaffing.online',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true
  })
);


app.use(express.json({ limit: '30mb' }));
app.use('/uploads', express.static('uploads'));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://localhost:8001';
const MATCH_THRESHOLD = Number(process.env.MATCH_THRESHOLD || 0.42);
const DUPLICATE_BLOCK_SECONDS = Number(process.env.DUPLICATE_BLOCK_SECONDS || 30);
const LIVENESS_REQUIRED = process.env.LIVENESS_REQUIRED === '1';
const LIVENESS_MIN_MOVEMENT = Number(process.env.LIVENESS_MIN_MOVEMENT || 0.03);
const GEOFENCE_REQUIRED = process.env.GEOFENCE_REQUIRED === '1';

const md5 = (v) => crypto.createHash('md5').update(String(v)).digest('hex');
const ok = (res, data = {}) => res.json({ success: true, ...data });
const fail = (res, code, message, extra = {}) => res.status(code).json({ success: false, message, ...extra });

async function getSingleEmbedding(imageBase64) {
  const response = await axios.post(`${AI_SERVICE_URL}/extract-embedding`, {
    image_base64: imageBase64
  });

  return response.data;
}

function cosineDistance(a, b) {
  const arrA = typeof a === 'string' ? JSON.parse(a) : a;
  const arrB = typeof b === 'string' ? JSON.parse(b) : b;

  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < arrA.length; i++) {
    dot += arrA[i] * arrB[i];
    normA += arrA[i] * arrA[i];
    normB += arrB[i] * arrB[i];
  }

  if (!normA || !normB) return 999;

  const similarity = dot / (Math.sqrt(normA) * Math.sqrt(normB));
  return 1 - similarity;
}
function getTargetCompanyId(req) {
  if (req.user.role === 'super_admin') {
    return req.query.company_id || req.body.company_id;
  }

  return req.user.company_id;
}

function requireCompanyId(req, res) {
  const companyId = getTargetCompanyId(req);

  if (!companyId) {
    fail(res, 400, 'Please select company first');
    return null;
  }

  return companyId;
}
const masterTableMap = {
  'packages': {
    table: 'master_packages',
    fields: ['name', 'code', 'max_users', 'max_locations', 'monthly_price', 'description', 'status']
  },
  'departments': {
    table: 'master_departments',
    fields: ['name', 'code', 'description', 'status']
  },
  'designations': {
    table: 'master_designations',
    fields: ['name', 'code', 'level_no', 'description', 'status']
  },
  'shifts': {
    table: 'master_shifts',
    fields: ['name', 'code', 'start_time', 'end_time', 'grace_minutes', 'half_day_minutes', 'full_day_minutes', 'status']
  },
  'employee-types': {
    table: 'master_employee_types',
    fields: ['name', 'code', 'description', 'status']
  },
  'industry-types': {
    table: 'master_industry_types',
    fields: ['name', 'code', 'description', 'status']
  },
  'company-sizes': {
    table: 'master_company_sizes',
    fields: ['name', 'min_employees', 'max_employees', 'description', 'status']
  },
  'leave-types': {
    table: 'master_leave_types',
    fields: ['name', 'code', 'paid_leave', 'annual_quota', 'description', 'status']
  },
  'attendance-modes': {
    table: 'master_attendance_modes',
    fields: ['name', 'code', 'requires_face', 'requires_location', 'description', 'status']
  }
};

function getMasterConfig(type) {
  return masterTableMap[type] || null;
}


function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role, company_id: user.company_id, employee_id: user.employee_id, location_id: user.location_id }, JWT_SECRET, { expiresIn: '12h' });
}

function auth(requiredRoles = []) {
  return async (req, res, next) => {
    try {
      const header = req.headers.authorization || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : '';
      if (!token) return fail(res, 401, 'Unauthorized');
      const decoded = jwt.verify(token, JWT_SECRET);
      if (requiredRoles.length && !requiredRoles.includes(decoded.role)) return fail(res, 403, 'Access denied');
      req.user = decoded;
      next();
    } catch (e) { return fail(res, 401, 'Invalid or expired token'); }
  };
}

function scopedCompany(req, companyId) {
  if (req.user.role === 'super_admin') return true;
  return Number(req.user.company_id) === Number(companyId);
}

async function ensureSchema() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS master_packages (
      id SERIAL PRIMARY KEY, name VARCHAR(100) UNIQUE NOT NULL, max_users INT NOT NULL,
      max_locations INT NOT NULL, monthly_price NUMERIC(12,2) DEFAULT 0, features JSONB DEFAULT '{}', status BOOLEAN DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS master_departments (id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, status BOOLEAN DEFAULT TRUE);
    CREATE TABLE IF NOT EXISTS master_designations (id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, status BOOLEAN DEFAULT TRUE);
    CREATE TABLE IF NOT EXISTS master_shifts (id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, start_time TIME, end_time TIME, grace_minutes INT DEFAULT 10, status BOOLEAN DEFAULT TRUE);
    CREATE TABLE IF NOT EXISTS master_employee_types (id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, status BOOLEAN DEFAULT TRUE);
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY, package_id INT REFERENCES master_packages(id), name VARCHAR(180) NOT NULL,
      legal_name VARCHAR(220), email VARCHAR(150), phone VARCHAR(30), logo_url TEXT, status VARCHAR(30) DEFAULT 'active',
      max_users INT DEFAULT 0, max_locations INT DEFAULT 0, subscription_start DATE DEFAULT CURRENT_DATE,
      subscription_end DATE DEFAULT (CURRENT_DATE + INTERVAL '1 year'), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT, location_id INT,
      name VARCHAR(160) NOT NULL, email VARCHAR(160) UNIQUE NOT NULL, phone VARCHAR(30), password_md5 VARCHAR(32) NOT NULL,
      role VARCHAR(40) NOT NULL, status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS company_locations (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), name VARCHAR(160) NOT NULL, code VARCHAR(60),
      address TEXT, latitude NUMERIC(12,8), longitude NUMERIC(12,8), geofence_radius_m INT DEFAULT 100,
      kiosk_key VARCHAR(80) UNIQUE DEFAULT encode(gen_random_bytes(12),'hex'), status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS employees (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_code VARCHAR(80), name VARCHAR(160) NOT NULL,
      email VARCHAR(160), phone VARCHAR(30), department_id INT REFERENCES master_departments(id), designation_id INT REFERENCES master_designations(id),
      employee_type_id INT REFERENCES master_employee_types(id), shift_id INT REFERENCES master_shifts(id), joining_date DATE,
      base_salary NUMERIC(12,2) DEFAULT 0, allow_any_location BOOLEAN DEFAULT FALSE, status BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(company_id, employee_code)
    );
    CREATE TABLE IF NOT EXISTS employee_faces (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id) ON DELETE CASCADE,
      embedding JSONB NOT NULL, sample_no INT DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS employee_location_map (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id) ON DELETE CASCADE,
      location_id INT REFERENCES company_locations(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(employee_id, location_id)
    );
    CREATE TABLE IF NOT EXISTS attendance_logs (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id), location_id INT REFERENCES company_locations(id),
      punch_type VARCHAR(10) NOT NULL, source VARCHAR(30) DEFAULT 'kiosk', employee_name VARCHAR(160), match_score FLOAT,
      liveness_pass BOOLEAN DEFAULT TRUE, latitude NUMERIC(12,8), longitude NUMERIC(12,8), distance_m FLOAT,
      face_index INT, marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS leave_requests (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id), leave_type VARCHAR(60),
      from_date DATE, to_date DATE, reason TEXT, status VARCHAR(30) DEFAULT 'pending', approved_by INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS payroll_runs (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), month INT, year INT, status VARCHAR(30) DEFAULT 'draft',
      generated_by INT, total_employees INT DEFAULT 0, total_payable NUMERIC(12,2) DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(company_id, month, year)
    );
    CREATE TABLE IF NOT EXISTS payroll_items (
      id SERIAL PRIMARY KEY, payroll_run_id INT REFERENCES payroll_runs(id) ON DELETE CASCADE, employee_id INT REFERENCES employees(id),
      present_days NUMERIC(8,2) DEFAULT 0, payable_days NUMERIC(8,2) DEFAULT 0, gross_salary NUMERIC(12,2) DEFAULT 0,
      deduction NUMERIC(12,2) DEFAULT 0, net_salary NUMERIC(12,2) DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_attendance_company_time ON attendance_logs(company_id, marked_at DESC);
    CREATE INDEX IF NOT EXISTS idx_attendance_employee_time ON attendance_logs(employee_id, marked_at DESC);
    CREATE INDEX IF NOT EXISTS idx_faces_company_employee ON employee_faces(company_id, employee_id);
  `);
  await seed();
}

async function seed() {
  await pool.query(`
    INSERT INTO master_packages(name,max_users,max_locations,monthly_price,features) VALUES
    ('Starter',50,2,2499,'{"face":true,"geofence":true,"payroll":false}'),
    ('Business',250,10,9999,'{"face":true,"geofence":true,"payroll":true,"leave":true}'),
    ('Enterprise',5000,500,0,'{"face":true,"geofence":true,"payroll":true,"leave":true,"api":true}')
    ON CONFLICT(name) DO NOTHING;
    INSERT INTO master_departments(name) VALUES ('Operations'),('HR'),('Finance'),('Security'),('Housekeeping'),('IT') ON CONFLICT(name) DO NOTHING;
    INSERT INTO master_designations(name) VALUES ('Manager'),('Supervisor'),('Executive'),('Worker'),('Guard'),('Admin') ON CONFLICT(name) DO NOTHING;
    INSERT INTO master_employee_types(name) VALUES ('Permanent'),('Contract'),('Part Time'),('Intern') ON CONFLICT(name) DO NOTHING;
    INSERT INTO master_shifts(name,start_time,end_time,grace_minutes) VALUES ('General','09:30','18:30',10),('Morning','06:00','14:00',10),('Evening','14:00','22:00',10),('Night','22:00','06:00',15) ON CONFLICT(name) DO NOTHING;
  `);
  const su = await pool.query(`SELECT id FROM users WHERE role='super_admin' LIMIT 1`);
  if (su.rows.length === 0) {
    await pool.query(`INSERT INTO users(name,email,password_md5,role) VALUES($1,$2,$3,'super_admin')`, ['Super Admin', 'superadmin@example.com', md5('admin123')]);
  }
}

async function aiExtractSingle(imageBase64) {
  const r = await axios.post(`${AI_SERVICE_URL}/extract-embedding`, { image_base64: imageBase64 }, { timeout: 30000 });
  return r.data;
}
async function aiExtractMultiple(imageBase64) {
  const r = await axios.post(`${AI_SERVICE_URL}/extract-multiple-embeddings`, { image_base64: imageBase64 }, { timeout: 30000 });
  return r.data;
}
async function aiCompareFrames(frames) {
  try {
    const r = await axios.post(`${AI_SERVICE_URL}/liveness-check`, { frames_base64: frames }, { timeout: 30000 });
    return r.data;
  } catch (e) { return { success: true, liveness_pass: true, movement_score: 1, message: 'Liveness fallback pass' }; }
}
function haversine(lat1, lon1, lat2, lon2) {
  if ([lat1,lon1,lat2,lon2].some(v => v === null || v === undefined || v === '')) return null;
  const R=6371000, toRad=d=>Number(d)*Math.PI/180;
  const dLat=toRad(lat2-lat1), dLon=toRad(lon2-lon1);
  const a=Math.sin(dLat/2)**2+Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)**2;
  return 2*R*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}
async function getFaces(companyId) {
  const { rows } = await pool.query(
    `
    SELECT
      f.embedding,
      e.id,
      e.employee_code,
      e.name,
      e.allow_any_location,
      e.status,
      e.employment_status
    FROM employee_faces f
    JOIN employees e ON e.id = f.employee_id
    WHERE f.company_id = $1
      AND e.company_id = $1
      AND e.status = true
      AND COALESCE(e.employment_status, 'active') IN ('active', 'probation', 'notice_period')
    `,
    [companyId]
  );

  return rows;
}
async function employeeAllowedAt(companyId, employeeId, locationId) {
  const result = await pool.query(
    `
    SELECT
      e.id AS employee_id,
      e.allow_any_location,
      COALESCE(l.allow_all_employees, false) AS location_allow_all_employees,
      CASE
        WHEN e.allow_any_location = true THEN true
        WHEN COALESCE(l.allow_all_employees, false) = true THEN true
        WHEN elm.employee_id IS NOT NULL THEN true
        ELSE false
      END AS location_allowed
    FROM employees e
    JOIN company_locations l
      ON l.id = $3
     AND l.company_id = $1
     AND l.status = true
    LEFT JOIN employee_location_map elm
      ON elm.employee_id = e.id
     AND elm.location_id = l.id
    WHERE e.id = $2
      AND e.company_id = $1
      AND e.status = true
    `,
    [companyId, employeeId, locationId]
  );

  if (!result.rows.length) {
    return {
      allowed: false,
      reason: 'INVALID_LOCATION',
      message: 'Invalid attendance location.'
    };
  }

  const row = result.rows[0];

  if (row.location_allowed) {
    return {
      allowed: true,
      reason: 'ALLOWED'
    };
  }

  return {
    allowed: false,
    reason: 'NOT_ASSIGNED_TO_LOCATION',
    message: 'Employee is not assigned to this location.'
  };
}
async function nextPunchType(companyId, employeeId) {
  const r = await pool.query(`SELECT punch_type FROM attendance_logs WHERE company_id=$1 AND employee_id=$2 ORDER BY marked_at DESC LIMIT 1`, [companyId, employeeId]);
  return r.rows.length && r.rows[0].punch_type === 'IN' ? 'OUT' : 'IN';
}
async function duplicateRecently(employeeId) {
  const r = await pool.query(`SELECT 1 FROM attendance_logs WHERE employee_id=$1 AND marked_at >= NOW() - ($2 || ' seconds')::interval LIMIT 1`, [employeeId, DUPLICATE_BLOCK_SECONDS]);
  return r.rows.length > 0;
}

app.get('/', (req,res)=>ok(res,{message:'Enterprise Face Attendance API'}));
app.get('/api/health', async (req,res)=>{
  const result = { backend:'ok', database:'unknown', ai_service:'unknown' };
  try { await pool.query('SELECT 1'); result.database='ok'; } catch(e){ result.database=e.message; }
  try { const r = await axios.get(AI_SERVICE_URL, {timeout:5000}); result.ai_service = r.data?.success ? 'ok' : 'not-ok'; } catch(e){ result.ai_service=e.message; }
  ok(res,result);
});

app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body;
  const userAgent = req.headers['user-agent'] || '';
  const ipAddress = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';

  try {
    const userCheck = await pool.query(
      `SELECT id, failed_login_attempts, locked_until FROM users WHERE lower(email)=lower($1) LIMIT 1`,
      [email]
    );

    if (userCheck.rows.length && userCheck.rows[0].locked_until && new Date(userCheck.rows[0].locked_until) > new Date()) {
      await pool.query(
        `INSERT INTO login_history(user_id,email,status,ip_address,user_agent,reason) VALUES($1,$2,'failed',$3,$4,'Account temporarily locked')`,
        [userCheck.rows[0].id, email, ipAddress, userAgent]
      );
      return fail(res, 423, 'Account is temporarily locked due to failed login attempts');
    }

    const r = await pool.query(
      `SELECT u.*, c.name company_name, c.logo_url
       FROM users u
       LEFT JOIN companies c ON c.id=u.company_id
       WHERE lower(u.email)=lower($1) AND u.password_md5=$2 AND u.status=true`,
      [email, md5(password)]
    );

    if (!r.rows.length) {
      if (userCheck.rows.length) {
        const attempts = Number(userCheck.rows[0].failed_login_attempts || 0) + 1;
        const lockSql = attempts >= 5 ? `, locked_until = NOW() + INTERVAL '15 minutes'` : '';
        await pool.query(
          `UPDATE users SET failed_login_attempts=$2 ${lockSql} WHERE id=$1`,
          [userCheck.rows[0].id, attempts]
        );
        await pool.query(
          `INSERT INTO login_history(user_id,email,status,ip_address,user_agent,reason) VALUES($1,$2,'failed',$3,$4,'Invalid credentials')`,
          [userCheck.rows[0].id, email, ipAddress, userAgent]
        );
      }
      return fail(res, 401, 'Invalid email or password');
    }

    const user = r.rows[0];
    await pool.query(`UPDATE users SET last_login_at=NOW(), failed_login_attempts=0, locked_until=NULL WHERE id=$1`, [user.id]);
    await pool.query(
      `INSERT INTO login_history(user_id,email,status,ip_address,user_agent,reason) VALUES($1,$2,'success',$3,$4,'Login successful')`,
      [user.id, email, ipAddress, userAgent]
    );

    delete user.password_md5;
    ok(res,{token:signToken(user), user});
  } catch(error) {
    console.error('Login Error:', error.message);
    fail(res, 500, 'Login failed', { error: error.message });
  }
});
app.get('/api/me', auth(), async (req,res)=>{
  const r = await pool.query(`SELECT u.id,u.name,u.email,u.role,u.company_id,u.employee_id,u.location_id,c.name company_name,c.logo_url FROM users u LEFT JOIN companies c ON c.id=u.company_id WHERE u.id=$1`, [req.user.id]);
  ok(res,{user:r.rows[0]});
});

app.get('/api/masters/:type', auth(), async (req,res)=>{
  const map = { packages:'master_packages', departments:'master_departments', designations:'master_designations', shifts:'master_shifts', employee_types:'master_employee_types' };
  const table = map[req.params.type]; if(!table) return fail(res,400,'Invalid master type');
  const r = await pool.query(`SELECT * FROM ${table} WHERE status=true ORDER BY id`);
  ok(res,{items:r.rows});
});

app.get('/api/super/companies', auth(['super_admin']), async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT 
        c.*,
        p.name AS package_name,
        p.max_users AS package_max_users,
        p.max_locations AS package_max_locations,
        u.id AS admin_user_id,
        u.name AS admin_name,
        u.email AS admin_email,
        u.phone AS admin_phone,
        COALESCE(emp_count.total_employees, 0) AS total_employees,
        COALESCE(loc_count.total_locations, 0) AS total_locations
      FROM companies c
      LEFT JOIN master_packages p ON p.id = c.package_id
      LEFT JOIN users u 
        ON u.company_id = c.id 
       AND u.role = 'company_admin'
       AND u.status = TRUE
      LEFT JOIN (
        SELECT company_id, COUNT(*) AS total_employees
        FROM employees
        GROUP BY company_id
      ) emp_count ON emp_count.company_id = c.id
      LEFT JOIN (
        SELECT company_id, COUNT(*) AS total_locations
        FROM company_locations
        GROUP BY company_id
      ) loc_count ON loc_count.company_id = c.id
      ORDER BY c.id DESC
    `);

    ok(res, { companies: r.rows });
  } catch (error) {
    console.error('Company List Error:', error.message);
    fail(res, 500, 'Unable to fetch companies', { error: error.message });
  }
});

app.post('/api/super/companies', auth(['super_admin']), async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      package_id,
      name,
      legal_name,
      company_code,
      industry_type,
      company_size,
      website,
      email,
      phone,
      gst_number,
      pan_number,
      cin_number,
      address_line1,
      address_line2,
      city,
      state,
      country,
      pincode,
      logo_url,
      primary_color,
      timezone,
      geofence_required,
      liveness_required,
      duplicate_block_seconds,
      subscription_start,
      subscription_end,
      admin_name,
      admin_email,
      admin_phone,
      admin_password
    } = req.body;

    if (!package_id) return fail(res, 400, 'Package is required');
    if (!name) return fail(res, 400, 'Company name is required');
    if (!email) return fail(res, 400, 'Company email is required');
    if (!admin_email) return fail(res, 400, 'Admin email is required');

    const pkg = await client.query(
      `SELECT * FROM master_packages WHERE id = $1 AND status = TRUE`,
      [package_id]
    );

    if (!pkg.rows.length) {
      return fail(res, 400, 'Package not found');
    }

    const existingAdmin = await client.query(
      `SELECT id FROM users WHERE lower(email) = lower($1)`,
      [admin_email]
    );

    if (existingAdmin.rows.length) {
      return fail(res, 400, 'Admin email already exists');
    }

    if (company_code) {
      const existingCode = await client.query(
        `SELECT id FROM companies WHERE lower(company_code) = lower($1)`,
        [company_code]
      );

      if (existingCode.rows.length) {
        return fail(res, 400, 'Company code already exists');
      }
    }

    await client.query('BEGIN');

    const p = pkg.rows[0];

    const companyResult = await client.query(
      `
      INSERT INTO companies (
        package_id,
        name,
        legal_name,
        company_code,
        industry_type,
        company_size,
        website,
        email,
        phone,
        gst_number,
        pan_number,
        cin_number,
        address_line1,
        address_line2,
        city,
        state,
        country,
        pincode,
        logo_url,
        primary_color,
        timezone,
        geofence_required,
        liveness_required,
        duplicate_block_seconds,
        max_users,
        max_locations,
        subscription_start,
        subscription_end,
        status
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        $11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
        $21,$22,$23,$24,$25,$26,$27,$28,'active'
      )
      RETURNING *
      `,
      [
        package_id,
        name,
        legal_name || null,
        company_code || null,
        industry_type || null,
        company_size || null,
        website || null,
        email,
        phone || null,
        gst_number || null,
        pan_number || null,
        cin_number || null,
        address_line1 || null,
        address_line2 || null,
        city || null,
        state || null,
        country || 'India',
        pincode || null,
        logo_url || null,
        primary_color || '#1976d2',
        timezone || 'Asia/Kolkata',
        geofence_required !== false,
        liveness_required !== false,
        Number(duplicate_block_seconds || 30),
        p.max_users,
        p.max_locations,
        subscription_start || null,
        subscription_end || null
      ]
    );

    const company = companyResult.rows[0];

    await client.query(
      `
      INSERT INTO users (
        company_id,
        name,
        email,
        phone,
        password_md5,
        role,
        status
      )
      VALUES ($1,$2,$3,$4,$5,'company_admin',TRUE)
      `,
      [
        company.id,
        admin_name || `${name} Admin`,
        admin_email,
        admin_phone || phone || null,
        md5(admin_password || 'admin123')
      ]
    );

    await client.query('COMMIT');

    ok(res, {
      message: 'Company onboarded successfully',
      company
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Company Create Error:', error.message);
    fail(res, 500, 'Company onboarding failed', { error: error.message });
  } finally {
    client.release();
  }
});
app.put('/api/super/companies/:id/status', auth(['super_admin']), async (req,res)=>{
  const { status } = req.body;
  const r = await pool.query(`UPDATE companies SET status=$1 WHERE id=$2 RETURNING *`, [status, req.params.id]);
  ok(res,{company:r.rows[0]});
});
app.put('/api/super/companies/:id', auth(['super_admin']), async (req, res) => {
  const client = await pool.connect();

  try {
    const companyId = req.params.id;

    const {
      package_id,
      name,
      legal_name,
      company_code,
      industry_type,
      company_size,
      website,
      email,
      phone,
      gst_number,
      pan_number,
      cin_number,
      address_line1,
      address_line2,
      city,
      state,
      country,
      pincode,
      logo_url,
      primary_color,
      timezone,
      geofence_required,
      liveness_required,
      duplicate_block_seconds,
      subscription_start,
      subscription_end,
      status,
      admin_user_id,
      admin_name,
      admin_email,
      admin_phone,
      admin_password
    } = req.body;

    if (!name) return fail(res, 400, 'Company name is required');
    if (!email) return fail(res, 400, 'Company email is required');

    const companyCheck = await client.query(
      `SELECT * FROM companies WHERE id = $1`,
      [companyId]
    );

    if (!companyCheck.rows.length) {
      return fail(res, 404, 'Company not found');
    }

    if (company_code) {
      const existingCode = await client.query(
        `SELECT id FROM companies WHERE lower(company_code) = lower($1) AND id <> $2`,
        [company_code, companyId]
      );

      if (existingCode.rows.length) {
        return fail(res, 400, 'Company code already exists');
      }
    }

    if (admin_email) {
      const existingAdmin = await client.query(
        `SELECT id FROM users WHERE lower(email) = lower($1) AND company_id <> $2`,
        [admin_email, companyId]
      );

      if (existingAdmin.rows.length) {
        return fail(res, 400, 'Admin email already exists in another company');
      }
    }

    let maxUsers = req.body.max_users;
    let maxLocations = req.body.max_locations;

    if (package_id) {
      const pkg = await client.query(
        `SELECT * FROM master_packages WHERE id = $1 AND status = TRUE`,
        [package_id]
      );

      if (!pkg.rows.length) {
        return fail(res, 400, 'Package not found');
      }

      maxUsers = pkg.rows[0].max_users;
      maxLocations = pkg.rows[0].max_locations;
    }

    await client.query('BEGIN');

    const companyResult = await client.query(
      `
      UPDATE companies
      SET
        package_id = $1,
        name = $2,
        legal_name = $3,
        company_code = $4,
        industry_type = $5,
        company_size = $6,
        website = $7,
        email = $8,
        phone = $9,
        gst_number = $10,
        pan_number = $11,
        cin_number = $12,
        address_line1 = $13,
        address_line2 = $14,
        city = $15,
        state = $16,
        country = $17,
        pincode = $18,
        logo_url = $19,
        primary_color = $20,
        timezone = $21,
        geofence_required = $22,
        liveness_required = $23,
        duplicate_block_seconds = $24,
        max_users = $25,
        max_locations = $26,
        subscription_start = $27,
        subscription_end = $28,
        status = $29,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $30
      RETURNING *
      `,
      [
        package_id || null,
        name,
        legal_name || null,
        company_code || null,
        industry_type || null,
        company_size || null,
        website || null,
        email,
        phone || null,
        gst_number || null,
        pan_number || null,
        cin_number || null,
        address_line1 || null,
        address_line2 || null,
        city || null,
        state || null,
        country || 'India',
        pincode || null,
        logo_url || null,
        primary_color || '#1976d2',
        timezone || 'Asia/Kolkata',
        geofence_required !== false,
        liveness_required !== false,
        Number(duplicate_block_seconds || 30),
        Number(maxUsers || 0),
        Number(maxLocations || 0),
        subscription_start || null,
        subscription_end || null,
        status || 'active',
        companyId
      ]
    );

    if (admin_user_id) {
      if (admin_password) {
        await client.query(
          `
          UPDATE users
          SET name = $1,
              email = $2,
              phone = $3,
              password_md5 = $4
          WHERE id = $5 AND company_id = $6 AND role = 'company_admin'
          `,
          [
            admin_name || `${name} Admin`,
            admin_email || email,
            admin_phone || phone || null,
            md5(admin_password),
            admin_user_id,
            companyId
          ]
        );
      } else {
        await client.query(
          `
          UPDATE users
          SET name = $1,
              email = $2,
              phone = $3
          WHERE id = $4 AND company_id = $5 AND role = 'company_admin'
          `,
          [
            admin_name || `${name} Admin`,
            admin_email || email,
            admin_phone || phone || null,
            admin_user_id,
            companyId
          ]
        );
      }
    } else if (admin_email) {
      await client.query(
        `
        INSERT INTO users (
          company_id,
          name,
          email,
          phone,
          password_md5,
          role,
          status
        )
        VALUES ($1,$2,$3,$4,$5,'company_admin',TRUE)
        `,
        [
          companyId,
          admin_name || `${name} Admin`,
          admin_email,
          admin_phone || phone || null,
          md5(admin_password || 'admin123')
        ]
      );
    }

    await client.query('COMMIT');

    ok(res, {
      message: 'Company updated successfully',
      company: companyResult.rows[0]
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Company Update Error:', error.message);
    fail(res, 500, 'Company update failed', { error: error.message });
  } finally {
    client.release();
  }
});
app.delete('/api/super/companies/:id', auth(['super_admin']), async (req, res) => {
  const client = await pool.connect();

  try {
    const companyId = req.params.id;

    const companyCheck = await client.query(
      `SELECT id, name FROM companies WHERE id = $1`,
      [companyId]
    );

    if (!companyCheck.rows.length) {
      return fail(res, 404, 'Company not found');
    }

    const empCount = await client.query(
      `SELECT COUNT(*)::int AS total FROM employees WHERE company_id = $1`,
      [companyId]
    );

    const locCount = await client.query(
      `SELECT COUNT(*)::int AS total FROM company_locations WHERE company_id = $1`,
      [companyId]
    );

    const attendanceCount = await client.query(
      `SELECT COUNT(*)::int AS total FROM attendance_logs WHERE company_id = $1`,
      [companyId]
    );

    if (
      empCount.rows[0].total > 0 ||
      locCount.rows[0].total > 0 ||
      attendanceCount.rows[0].total > 0
    ) {
      return fail(
        res,
        400,
        'Company has employees, locations or attendance data. Please deactivate instead of delete.'
      );
    }

    await client.query('BEGIN');

    await client.query(
      `DELETE FROM users WHERE company_id = $1`,
      [companyId]
    );

    await client.query(
      `DELETE FROM companies WHERE id = $1`,
      [companyId]
    );

    await client.query('COMMIT');

    ok(res, {
      message: 'Company deleted successfully'
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Company Delete Error:', error.message);
    fail(res, 500, 'Company delete failed', { error: error.message });
  } finally {
    client.release();
  }
});

app.get('/api/dashboard', auth(), async (req,res)=>{
  const companyId = req.user.role==='super_admin' ? req.query.company_id : req.user.company_id;
  if(req.user.role==='super_admin' && !companyId) {
    const a = await pool.query(`SELECT count(*) companies FROM companies`); const u = await pool.query(`SELECT count(*) users FROM users`);
    return ok(res,{scope:'super', cards:{companies:Number(a.rows[0].companies), users:Number(u.rows[0].users)}});
  }
  const cards = {};
  cards.employees = Number((await pool.query(`SELECT count(*) n FROM employees WHERE company_id=$1`,[companyId])).rows[0].n);
  cards.locations = Number((await pool.query(`SELECT count(*) n FROM company_locations WHERE company_id=$1`,[companyId])).rows[0].n);
  cards.today_in = Number((await pool.query(`SELECT count(DISTINCT employee_id) n FROM attendance_logs WHERE company_id=$1 AND punch_type='IN' AND marked_at::date=CURRENT_DATE`,[companyId])).rows[0].n);
  cards.today_out = Number((await pool.query(`SELECT count(*) n FROM attendance_logs WHERE company_id=$1 AND punch_type='OUT' AND marked_at::date=CURRENT_DATE`,[companyId])).rows[0].n);
  const recent = await pool.query(`SELECT a.*, l.name location_name FROM attendance_logs a LEFT JOIN company_locations l ON l.id=a.location_id WHERE a.company_id=$1 ORDER BY a.marked_at DESC LIMIT 20`, [companyId]);
  ok(res,{scope:'company', cards, recent:recent.rows});
});

app.get('/api/company/locations', auth(['super_admin', 'company_admin', 'location_admin']), async (req, res) => {
  try {
    const companyId = requireCompanyId(req, res);
    if (!companyId) return;

    const result = await pool.query(
      `
      SELECT 
        l.*,
        c.name AS company_name,
        COALESCE(mapped.total_mapped_employees, 0) AS total_mapped_employees
      FROM company_locations l
      LEFT JOIN companies c ON c.id = l.company_id
      LEFT JOIN (
        SELECT location_id, COUNT(*) AS total_mapped_employees
        FROM employee_location_map
        GROUP BY location_id
      ) mapped ON mapped.location_id = l.id
      WHERE l.company_id = $1
      ORDER BY l.id DESC
      `,
      [companyId]
    );

    ok(res, { locations: result.rows });
  } catch (error) {
    console.error('Location List Error:', error.message);
    fail(res, 500, 'Unable to fetch locations', { error: error.message });
  }
});
app.post('/api/company/locations', auth(['super_admin', 'company_admin']), async (req, res) => {
  try {
    const companyId = requireCompanyId(req, res);
    if (!companyId) return;

    const {
      name,
      code,
      address,
      latitude,
      longitude,
      geofence_radius_m,
      timezone,
      contact_person,
      contact_phone,
      kiosk_enabled,
      self_attendance_enabled,
      allow_all_employees,
      status
    } = req.body;

    if (!name) return fail(res, 400, 'Location name is required');
    if (!code) return fail(res, 400, 'Location code is required');
    if (!latitude) return fail(res, 400, 'Latitude is required');
    if (!longitude) return fail(res, 400, 'Longitude is required');

    const company = await pool.query(
      `SELECT max_locations FROM companies WHERE id = $1`,
      [companyId]
    );

    if (!company.rows.length) {
      return fail(res, 400, 'Company not found');
    }

    const currentCount = await pool.query(
      `SELECT COUNT(*)::int AS total FROM company_locations WHERE company_id = $1`,
      [companyId]
    );

    if (currentCount.rows[0].total >= company.rows[0].max_locations) {
      return fail(res, 400, 'Package location limit reached');
    }

    const duplicate = await pool.query(
      `
      SELECT id 
      FROM company_locations 
      WHERE company_id = $1 
        AND lower(code) = lower($2)
      `,
      [companyId, code]
    );

    if (duplicate.rows.length) {
      return fail(res, 400, 'Location code already exists');
    }

    const result = await pool.query(
      `
      INSERT INTO company_locations (
        company_id,
        name,
        code,
        address,
        latitude,
        longitude,
        geofence_radius_m,
        timezone,
        contact_person,
        contact_phone,
        kiosk_enabled,
        self_attendance_enabled,
        allow_all_employees,
        status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *
      `,
      [
        companyId,
        name,
        code,
        address || null,
        Number(latitude),
        Number(longitude),
        Number(geofence_radius_m || 100),
        timezone || 'Asia/Kolkata',
        contact_person || null,
        contact_phone || null,
        kiosk_enabled !== false,
        self_attendance_enabled !== false,
        allow_all_employees === true,
        status !== false
      ]
    );

    ok(res, {
      message: 'Location created successfully',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Location Create Error:', error.message);
    fail(res, 500, 'Location create failed', { error: error.message });
  }
});

app.get('/api/company/employees', auth(['super_admin', 'company_admin']), async (req, res) => {
  try {
    const companyId = requireCompanyId(req, res);
    if (!companyId) return;

    const result = await pool.query(
      `
      SELECT
        e.*,
        c.name AS company_name,
        d.name AS department_name,
        des.name AS designation_name,
        et.name AS employee_type_name,
        s.name AS shift_name,
        s.start_time AS shift_start_time,
        s.end_time AS shift_end_time,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT elm.location_id), NULL),
          ARRAY[]::integer[]
        ) AS location_ids,
        COALESCE(
          STRING_AGG(DISTINCT cl.name, ', '),
          ''
        ) AS location_names
      FROM employees e
      LEFT JOIN companies c ON c.id = e.company_id
      LEFT JOIN master_departments d ON d.id = e.department_id
      LEFT JOIN master_designations des ON des.id = e.designation_id
      LEFT JOIN master_employee_types et ON et.id = e.employee_type_id
      LEFT JOIN master_shifts s ON s.id = e.shift_id
      LEFT JOIN employee_location_map elm ON elm.employee_id = e.id
      LEFT JOIN company_locations cl ON cl.id = elm.location_id
      WHERE e.company_id = $1
      GROUP BY 
        e.id,
        c.name,
        d.name,
        des.name,
        et.name,
        s.name,
        s.start_time,
        s.end_time
      ORDER BY e.id DESC
      `,
      [companyId]
    );

    ok(res, {
      employees: result.rows
    });
  } catch (error) {
    console.error('Employee List Error:', error.message);
    fail(res, 500, 'Unable to fetch employees', { error: error.message });
  }
});
app.post('/api/company/employees', auth(['super_admin', 'company_admin']), async (req, res) => {
  const client = await pool.connect();

  try {
    const companyId = requireCompanyId(req, res);
    if (!companyId) return;

    const {
      employee_code,
      name,
      email,
      official_email,
      phone,
      alternate_phone,
      password,

      gender,
      dob,
      father_name,
      blood_group,

      department_id,
      designation_id,
      employee_type_id,
      shift_id,
      location_ids,

      joining_date,
      probation_end_date,
      reporting_manager,
      employment_status,

      base_salary,
      bank_name,
      bank_account_no,
      ifsc_code,
      pf_number,
      esi_number,
      pan_number,
      aadhaar_number,

      address_line1,
      address_line2,
      city,
      state,
      pincode,

      emergency_contact_name,
      emergency_contact_phone,

      allow_any_location,
      self_attendance_allowed,
      overtime_allowed,
      late_mark_allowed,
      status
    } = req.body;

    if (!employee_code) return fail(res, 400, 'Employee code is required');
    if (!name) return fail(res, 400, 'Employee name is required');
    if (!email) return fail(res, 400, 'Employee login email is required');
    if (!phone) return fail(res, 400, 'Phone number is required');
    if (!department_id) return fail(res, 400, 'Department is required');
    if (!designation_id) return fail(res, 400, 'Designation is required');
    if (!employee_type_id) return fail(res, 400, 'Employee type is required');
    if (!shift_id) return fail(res, 400, 'Shift is required');

    if (!allow_any_location && (!location_ids || location_ids.length === 0)) {
      return fail(res, 400, 'Please select at least one mapped location or enable Allow Any Location');
    }

    const company = await client.query(
      `SELECT max_users FROM companies WHERE id = $1`,
      [companyId]
    );

    if (!company.rows.length) {
      return fail(res, 400, 'Company not found');
    }

    const currentEmployeeCount = await client.query(
      `SELECT COUNT(*)::int AS total FROM employees WHERE company_id = $1`,
      [companyId]
    );

    if (currentEmployeeCount.rows[0].total >= company.rows[0].max_users) {
      return fail(res, 400, 'Package employee/user limit reached');
    }

    const duplicateCode = await client.query(
      `
      SELECT id 
      FROM employees 
      WHERE company_id = $1 
        AND lower(employee_code) = lower($2)
      `,
      [companyId, employee_code]
    );

    if (duplicateCode.rows.length) {
      return fail(res, 400, 'Employee code already exists');
    }

    const duplicateEmail = await client.query(
      `
      SELECT id 
      FROM users 
      WHERE lower(email) = lower($1)
      `,
      [email]
    );

    if (duplicateEmail.rows.length) {
      return fail(res, 400, 'Login email already exists');
    }

    await client.query('BEGIN');

    const employeeResult = await client.query(
      `
      INSERT INTO employees (
        company_id,
        employee_code,
        name,
        email,
        official_email,
        phone,
        alternate_phone,

        gender,
        dob,
        father_name,
        blood_group,

        department_id,
        designation_id,
        employee_type_id,
        shift_id,

        joining_date,
        probation_end_date,
        reporting_manager,
        employment_status,

        base_salary,
        bank_name,
        bank_account_no,
        ifsc_code,
        pf_number,
        esi_number,
        pan_number,
        aadhaar_number,

        address_line1,
        address_line2,
        city,
        state,
        pincode,

        emergency_contact_name,
        emergency_contact_phone,

        allow_any_location,
        self_attendance_allowed,
        overtime_allowed,
        late_mark_allowed,
        status
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11,
        $12,$13,$14,$15,
        $16,$17,$18,$19,
        $20,$21,$22,$23,$24,$25,$26,$27,
        $28,$29,$30,$31,$32,
        $33,$34,
        $35,$36,$37,$38,$39
      )
      RETURNING *
      `,
      [
        companyId,
        employee_code,
        name,
        email,
        official_email || null,
        phone,
        alternate_phone || null,

        gender || null,
        dob || null,
        father_name || null,
        blood_group || null,

        department_id,
        designation_id,
        employee_type_id,
        shift_id,

        joining_date || null,
        probation_end_date || null,
        reporting_manager || null,
        employment_status || 'active',

        Number(base_salary || 0),
        bank_name || null,
        bank_account_no || null,
        ifsc_code || null,
        pf_number || null,
        esi_number || null,
        pan_number || null,
        aadhaar_number || null,

        address_line1 || null,
        address_line2 || null,
        city || null,
        state || null,
        pincode || null,

        emergency_contact_name || null,
        emergency_contact_phone || null,

        allow_any_location === true,
        self_attendance_allowed !== false,
        overtime_allowed === true,
        late_mark_allowed !== false,
        status !== false
      ]
    );

    const employee = employeeResult.rows[0];

    await client.query(
      `
      INSERT INTO users (
        company_id,
        employee_id,
        name,
        email,
        phone,
        password_md5,
        role,
        status
      )
      VALUES ($1,$2,$3,$4,$5,$6,'employee',$7)
      `,
      [
        companyId,
        employee.id,
        name,
        email,
        phone,
        md5(password || 'employee123'),
        status !== false
      ]
    );

    if (!allow_any_location && Array.isArray(location_ids)) {
      for (const locationId of location_ids) {
        await client.query(
          `
          INSERT INTO employee_location_map (
            company_id,
            employee_id,
            location_id
          )
          VALUES ($1,$2,$3)
          ON CONFLICT (employee_id, location_id) DO NOTHING
          `,
          [companyId, employee.id, locationId]
        );
      }
    }

    await client.query('COMMIT');

    ok(res, {
      message: 'Employee created successfully',
      employee
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Employee Create Error:', error.message);
    fail(res, 500, 'Employee create failed', { error: error.message });
  } finally {
    client.release();
  }
});
app.post('/api/company/employees/:id/face', auth(['company_admin','super_admin','employee']), async (req,res)=>{
  const { imageBase64 } = req.body;
  const empId = req.user.role==='employee' ? req.user.employee_id : req.params.id;
  const emp = await pool.query(`SELECT * FROM employees WHERE id=$1`, [empId]); if(!emp.rows.length) return fail(res,404,'Employee not found');
  if(req.user.role!=='super_admin' && Number(emp.rows[0].company_id)!==Number(req.user.company_id)) return fail(res,403,'Access denied');
  const ai = await aiExtractSingle(imageBase64); if(!ai.success) return fail(res,400,ai.message || 'Face not detected');
  const count = await pool.query(`SELECT count(*) n FROM employee_faces WHERE employee_id=$1`, [empId]);
  const r = await pool.query(`INSERT INTO employee_faces(company_id,employee_id,embedding,sample_no) VALUES($1,$2,$3,$4) RETURNING id`, [emp.rows[0].company_id, empId, JSON.stringify(ai.embedding), Number(count.rows[0].n)+1]);
  ok(res,{message:'Face sample saved', face_id:r.rows[0].id});
});
app.post('/api/company/employees/:id/locations', auth(['company_admin','super_admin']), async (req,res)=>{
  const companyId = req.user.role==='super_admin' ? req.body.company_id : req.user.company_id;
  const { location_ids = [], allow_any_location = false } = req.body;
  await pool.query(`UPDATE employees SET allow_any_location=$1 WHERE id=$2 AND company_id=$3`, [!!allow_any_location, req.params.id, companyId]);
  await pool.query(`DELETE FROM employee_location_map WHERE employee_id=$1 AND company_id=$2`, [req.params.id, companyId]);
  for(const loc of location_ids) await pool.query(`INSERT INTO employee_location_map(company_id,employee_id,location_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, [companyId, req.params.id, loc]);
  ok(res,{message:'Location mapping updated'});
});
app.put('/api/company/employees/:id', auth(['super_admin', 'company_admin']), async (req, res) => {
  const client = await pool.connect();

  try {
    const companyId = requireCompanyId(req, res);
    if (!companyId) return;

    const employeeId = req.params.id;

    const {
      employee_code,
      name,
      email,
      official_email,
      phone,
      alternate_phone,
      password,

      gender,
      dob,
      father_name,
      blood_group,

      department_id,
      designation_id,
      employee_type_id,
      shift_id,
      location_ids,

      joining_date,
      probation_end_date,
      reporting_manager,
      employment_status,

      base_salary,
      bank_name,
      bank_account_no,
      ifsc_code,
      pf_number,
      esi_number,
      pan_number,
      aadhaar_number,

      address_line1,
      address_line2,
      city,
      state,
      pincode,

      emergency_contact_name,
      emergency_contact_phone,

      allow_any_location,
      self_attendance_allowed,
      overtime_allowed,
      late_mark_allowed,
      status
    } = req.body;

    if (!employee_code) return fail(res, 400, 'Employee code is required');
    if (!name) return fail(res, 400, 'Employee name is required');
    if (!email) return fail(res, 400, 'Employee login email is required');
    if (!phone) return fail(res, 400, 'Phone number is required');

    if (!allow_any_location && (!location_ids || location_ids.length === 0)) {
      return fail(res, 400, 'Please select at least one mapped location or enable Allow Any Location');
    }

    const employeeCheck = await client.query(
      `SELECT * FROM employees WHERE id = $1 AND company_id = $2`,
      [employeeId, companyId]
    );

    if (!employeeCheck.rows.length) {
      return fail(res, 404, 'Employee not found');
    }

    const duplicateCode = await client.query(
      `
      SELECT id 
      FROM employees 
      WHERE company_id = $1 
        AND lower(employee_code) = lower($2)
        AND id <> $3
      `,
      [companyId, employee_code, employeeId]
    );

    if (duplicateCode.rows.length) {
      return fail(res, 400, 'Employee code already exists');
    }

    const duplicateEmail = await client.query(
      `
      SELECT id 
      FROM users 
      WHERE lower(email) = lower($1)
        AND employee_id <> $2
      `,
      [email, employeeId]
    );

    if (duplicateEmail.rows.length) {
      return fail(res, 400, 'Login email already exists');
    }

    await client.query('BEGIN');

    const employeeResult = await client.query(
      `
      UPDATE employees
      SET
        employee_code = $1,
        name = $2,
        email = $3,
        official_email = $4,
        phone = $5,
        alternate_phone = $6,

        gender = $7,
        dob = $8,
        father_name = $9,
        blood_group = $10,

        department_id = $11,
        designation_id = $12,
        employee_type_id = $13,
        shift_id = $14,

        joining_date = $15,
        probation_end_date = $16,
        reporting_manager = $17,
        employment_status = $18,

        base_salary = $19,
        bank_name = $20,
        bank_account_no = $21,
        ifsc_code = $22,
        pf_number = $23,
        esi_number = $24,
        pan_number = $25,
        aadhaar_number = $26,

        address_line1 = $27,
        address_line2 = $28,
        city = $29,
        state = $30,
        pincode = $31,

        emergency_contact_name = $32,
        emergency_contact_phone = $33,

        allow_any_location = $34,
        self_attendance_allowed = $35,
        overtime_allowed = $36,
        late_mark_allowed = $37,
        status = $38,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $39
        AND company_id = $40
      RETURNING *
      `,
      [
        employee_code,
        name,
        email,
        official_email || null,
        phone,
        alternate_phone || null,

        gender || null,
        dob || null,
        father_name || null,
        blood_group || null,

        department_id || null,
        designation_id || null,
        employee_type_id || null,
        shift_id || null,

        joining_date || null,
        probation_end_date || null,
        reporting_manager || null,
        employment_status || 'active',

        Number(base_salary || 0),
        bank_name || null,
        bank_account_no || null,
        ifsc_code || null,
        pf_number || null,
        esi_number || null,
        pan_number || null,
        aadhaar_number || null,

        address_line1 || null,
        address_line2 || null,
        city || null,
        state || null,
        pincode || null,

        emergency_contact_name || null,
        emergency_contact_phone || null,

        allow_any_location === true,
        self_attendance_allowed !== false,
        overtime_allowed === true,
        late_mark_allowed !== false,
        status !== false,

        employeeId,
        companyId
      ]
    );

    if (password) {
      await client.query(
        `
        UPDATE users
        SET
          name = $1,
          email = $2,
          phone = $3,
          password_md5 = $4,
          status = $5
        WHERE employee_id = $6
          AND company_id = $7
          AND role = 'employee'
        `,
        [
          name,
          email,
          phone,
          md5(password),
          status !== false,
          employeeId,
          companyId
        ]
      );
    } else {
      await client.query(
        `
        UPDATE users
        SET
          name = $1,
          email = $2,
          phone = $3,
          status = $4
        WHERE employee_id = $5
          AND company_id = $6
          AND role = 'employee'
        `,
        [
          name,
          email,
          phone,
          status !== false,
          employeeId,
          companyId
        ]
      );
    }

    await client.query(
      `DELETE FROM employee_location_map WHERE employee_id = $1 AND company_id = $2`,
      [employeeId, companyId]
    );

    if (!allow_any_location && Array.isArray(location_ids)) {
      for (const locationId of location_ids) {
        await client.query(
          `
          INSERT INTO employee_location_map (
            company_id,
            employee_id,
            location_id
          )
          VALUES ($1,$2,$3)
          ON CONFLICT (employee_id, location_id) DO NOTHING
          `,
          [companyId, employeeId, locationId]
        );
      }
    }

    await client.query('COMMIT');

    ok(res, {
      message: 'Employee updated successfully',
      employee: employeeResult.rows[0]
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Employee Update Error:', error.message);
    fail(res, 500, 'Employee update failed', { error: error.message });
  } finally {
    client.release();
  }
});
app.delete('/api/company/locations/:id', auth(['super_admin', 'company_admin']), async (req, res) => {
  try {
    const companyId = requireCompanyId(req, res);
    if (!companyId) return;

    const locationId = req.params.id;

    const attendanceCount = await pool.query(
      `
      SELECT COUNT(*)::int AS total
      FROM attendance_logs
      WHERE company_id = $1
        AND location_id = $2
      `,
      [companyId, locationId]
    );

    if (attendanceCount.rows[0].total > 0) {
      return fail(
        res,
        400,
        'This location has attendance data. Please deactivate instead of delete.'
      );
    }

    await pool.query(
      `
      DELETE FROM employee_location_map 
      WHERE location_id = $1
      `,
      [locationId]
    );

    const result = await pool.query(
      `
      DELETE FROM company_locations
      WHERE id = $1
        AND company_id = $2
      RETURNING id
      `,
      [locationId, companyId]
    );

    if (!result.rows.length) {
      return fail(res, 404, 'Location not found');
    }

    ok(res, {
      message: 'Location deleted successfully'
    });
  } catch (error) {
    console.error('Location Delete Error:', error.message);
    fail(res, 500, 'Location delete failed', { error: error.message });
  }
});
app.post(
  '/api/company/employees/:id/face-test',
  auth(['super_admin', 'company_admin', 'employee']),
  async (req, res) => {
    try {
      const employeeId = req.params.id;

      const companyId =
        req.user.role === 'super_admin'
          ? req.query.company_id || req.body.company_id
          : req.user.company_id;

      if (!companyId) {
        return fail(res, 400, 'Please select company first');
      }

      if (
        req.user.role === 'employee' &&
        Number(req.user.employee_id) !== Number(employeeId)
      ) {
        return fail(res, 403, 'You can test only your own face');
      }

      const { imageBase64 } = req.body;

      if (!imageBase64) {
        return fail(res, 400, 'Image is required');
      }

      const employeeResult = await pool.query(
        `
        SELECT id, employee_code, name, company_id
        FROM employees
        WHERE id = $1
          AND company_id = $2
        `,
        [employeeId, companyId]
      );

      if (!employeeResult.rows.length) {
        return fail(res, 404, 'Employee not found');
      }

      const employee = employeeResult.rows[0];

      const faceResult = await pool.query(
        `
        SELECT id, embedding
        FROM employee_faces
        WHERE employee_id = $1
        ORDER BY id DESC
        `,
        [employeeId]
      );

      if (!faceResult.rows.length) {
        return ok(res, {
          matched: false,
          message: 'No enrolled face sample found. Please enroll face first.',
          employee
        });
      }

      const aiResult = await getSingleEmbedding(imageBase64);

      if (!aiResult.success) {
        return ok(res, {
          matched: false,
          message: aiResult.message || 'Face not detected',
          employee
        });
      }

      const liveEmbedding = aiResult.embedding;

      let bestDistance = 999;

      for (const row of faceResult.rows) {
        const savedEmbedding = row.embedding;
        const distance = cosineDistance(liveEmbedding, savedEmbedding);

        if (distance < bestDistance) {
          bestDistance = distance;
        }
      }

      const threshold = Number(process.env.MATCH_THRESHOLD || 0.42);

      if (bestDistance <= threshold) {
        return ok(res, {
          matched: true,
          message: 'Face matched successfully. Attendance ke liye face ready hai.',
          employee,
          distance: bestDistance,
          threshold
        });
      }

      return ok(res, {
        matched: false,
        message:
          'Face enrolled sample se match nahi hua. Better lighting me 3-5 samples fir se enroll karein.',
        employee,
        distance: bestDistance,
        threshold
      });
    } catch (error) {
      console.error('Face Test Error:', error.message);
      fail(res, 500, 'Face test failed', { error: error.message });
    }
  }
);
app.post('/api/attendance/kiosk', auth(['company_admin', 'location_admin', 'super_admin']), async (req, res) => {
  try {
    const companyId = getTargetCompanyId(req);
    const locationId = req.body.location_id || req.user.location_id;

    const {
      imageBase64,
      frames = [],
      latitude,
      longitude
    } = req.body;

    if (!companyId) {
      return fail(res, 400, 'Please select company first');
    }

    if (!locationId) {
      return fail(res, 400, 'Please select attendance location');
    }

    if (!imageBase64) {
      return fail(res, 400, 'Image is required');
    }

    const locationResult = await pool.query(
      `
      SELECT *
      FROM company_locations
      WHERE id = $1
        AND company_id = $2
        AND status = true
      `,
      [locationId, companyId]
    );

    if (!locationResult.rows.length) {
      return fail(res, 400, 'Invalid location');
    }

    const location = locationResult.rows[0];

    const live = LIVENESS_REQUIRED
      ? await aiCompareFrames(frames.length ? frames : [imageBase64])
      : { liveness_pass: true, movement_score: 1 };

    if (LIVENESS_REQUIRED && !live.liveness_pass) {
      return ok(res, {
        matched: false,
        message: 'Static photo blocked',
        liveness: live,
        matches: [],
        unmatched_faces: []
      });
    }

    const ai = await aiExtractMultiple(imageBase64);

    if (!ai.success) {
      return ok(res, {
        matched: false,
        face_detected: false,
        no_face: true,
        message: ai.message || 'No face detected',
        matches: [],
        unmatched_faces: [],
        liveness: live
      });
    }

    const enrolledFaces = await getFaces(companyId);

    if (!enrolledFaces.length) {
      return ok(res, {
        matched: false,
        face_detected: true,
        message: 'No enrolled employee face found',
        matches: [],
        unmatched_faces: [],
        liveness: live
      });
    }

    const matches = [];
    const unmatched_faces = [];
    const seenEmployees = new Set();

    for (const face of ai.faces || []) {
      let best = null;
      let bestDistance = 999;

      for (const enrolled of enrolledFaces) {
        const distance = cosineDistance(face.embedding, enrolled.embedding);

        if (distance < bestDistance) {
          bestDistance = distance;
          best = enrolled;
        }
      }

      if (!best || bestDistance > MATCH_THRESHOLD) {
        unmatched_faces.push({
          face_index: face.face_index,
          message: 'No enrolled employee matched',
          distance: bestDistance,
          threshold: MATCH_THRESHOLD
        });
        continue;
      }

      if (seenEmployees.has(best.id)) {
        continue;
      }

      seenEmployees.add(best.id);

      const access = await employeeAllowedAt(companyId, best.id, locationId);

      const employeePayload = {
        id: best.id,
        employee_code: best.employee_code,
        name: best.name,
        allow_any_location: best.allow_any_location
      };

      if (!access.allowed) {
        matches.push({
          employee: employeePayload,
          attendance_marked: false,
          duplicate: false,
          not_assigned: true,
          location_allowed: false,
          reason: access.reason,
          message:
            access.reason === 'INVALID_LOCATION'
              ? 'Invalid attendance location.'
              : `${best.name}, you are not assigned to this location. Attendance cannot be marked here.`,
          distance: bestDistance,
          threshold: MATCH_THRESHOLD,
          face_index: face.face_index
        });

        continue;
      }

      const isDuplicate = await duplicateRecently(best.id);

      if (isDuplicate) {
        matches.push({
          employee: employeePayload,
          attendance_marked: false,
          duplicate: true,
          not_assigned: false,
          location_allowed: true,
          message: `${best.name}, attendance was already marked recently.`,
          distance: bestDistance,
          threshold: MATCH_THRESHOLD,
          face_index: face.face_index
        });

        continue;
      }

      const punch = await nextPunchType(companyId, best.id);

      let distance_m = null;

      if (latitude && longitude && location.latitude && location.longitude) {
        distance_m = haversine(
          latitude,
          longitude,
          location.latitude,
          location.longitude
        );
      }

      if (
        GEOFENCE_REQUIRED &&
        distance_m !== null &&
        distance_m > Number(location.geofence_radius_m || 100)
      ) {
        matches.push({
          employee: employeePayload,
          attendance_marked: false,
          duplicate: false,
          not_assigned: false,
          location_allowed: true,
          geofence_allowed: false,
          reason: 'OUTSIDE_GEOFENCE',
          message: `${best.name}, you are outside the geofence. Attendance cannot be marked here.`,
          distance_m,
          distance: bestDistance,
          threshold: MATCH_THRESHOLD,
          face_index: face.face_index
        });

        continue;
      }

      await pool.query(
        `
        INSERT INTO attendance_logs (
          company_id,
          employee_id,
          location_id,
          punch_type,
          source,
          employee_name,
          match_score,
          liveness_pass,
          latitude,
          longitude,
          distance_m,
          face_index
        )
        VALUES ($1,$2,$3,$4,'kiosk',$5,$6,$7,$8,$9,$10,$11)
        `,
        [
          companyId,
          best.id,
          locationId,
          punch,
          best.name,
          bestDistance,
          live.liveness_pass !== false,
          latitude || null,
          longitude || null,
          distance_m,
          face.face_index
        ]
      );

      matches.push({
        employee: employeePayload,
        punch_type: punch,
        attendance_marked: true,
        duplicate: false,
        not_assigned: false,
        location_allowed: true,
        message: `${best.name} ${punch} marked successfully.`,
        distance: bestDistance,
        threshold: MATCH_THRESHOLD,
        face_index: face.face_index
      });
    }

    const markedNames = matches
      .filter((m) => m.attendance_marked)
      .map((m) => `${m.employee.name} ${m.punch_type}`);

    const notAssignedNames = matches
      .filter((m) => m.not_assigned)
      .map((m) => m.employee.name);

    let message = 'No enrolled employee matched';

    if (markedNames.length) {
      message = `Attendance marked: ${markedNames.join(', ')}`;
    } else if (notAssignedNames.length) {
      message = `${notAssignedNames.join(', ')} not assigned to this location`;
    } else if (unmatched_faces.length) {
      message = 'Face detected but no enrolled employee matched';
    }

    return ok(res, {
      matched: matches.length > 0,
      face_detected: true,
      face_count: ai.face_count || ai.faces?.length || 0,
      message,
      matches,
      unmatched_faces,
      liveness: live,
      location: {
        id: location.id,
        name: location.name,
        allow_all_employees: location.allow_all_employees
      }
    });
  } catch (e) {
    console.error('Kiosk Attendance Error:', e.message);

    return fail(res, 500, 'Server error during kiosk attendance', {
      error: e.message
    });
  }
});

app.post('/api/attendance/self', auth(['employee']), async (req, res) => {
  try {
    const companyId = req.user.company_id;
    const employeeId = req.user.employee_id;

    const {
      imageBase64,
      frames = [],
      latitude,
      longitude,
      location_id,
      gps_accuracy
    } = req.body;

    if (!companyId) {
      return fail(res, 400, 'Company not found in login session');
    }

    if (!employeeId) {
      return fail(res, 400, 'Employee not found in login session');
    }

    if (!imageBase64) {
      return fail(res, 400, 'Image is required');
    }

    const employeeResult = await pool.query(
      `
      SELECT
        id,
        company_id,
        employee_code,
        name,
        allow_any_location,
        self_attendance_allowed,
        status,
        employment_status
      FROM employees
      WHERE id = $1
        AND company_id = $2
      `,
      [employeeId, companyId]
    );

    if (!employeeResult.rows.length) {
      return fail(res, 404, 'Employee profile not found');
    }

    const employee = employeeResult.rows[0];

    if (employee.status === false) {
      return fail(res, 403, 'Employee account is inactive');
    }

    if (employee.self_attendance_allowed === false) {
      return fail(res, 403, 'Self attendance is not allowed for this employee');
    }

    if (
      employee.employment_status &&
      !['active', 'probation', 'notice_period'].includes(employee.employment_status)
    ) {
      return fail(res, 403, 'Employee is not active for attendance');
    }

    let locationId = location_id || null;
    let distance_m = null;
    let selectedLocation = null;

    if (locationId) {
      const locationResult = await pool.query(
        `
        SELECT *
        FROM company_locations
        WHERE id = $1
          AND company_id = $2
          AND status = true
        `,
        [locationId, companyId]
      );

      if (!locationResult.rows.length) {
        return fail(res, 400, 'Invalid location');
      }

      selectedLocation = locationResult.rows[0];

      if (
        latitude &&
        longitude &&
        selectedLocation.latitude &&
        selectedLocation.longitude
      ) {
        distance_m = haversine(
          latitude,
          longitude,
          selectedLocation.latitude,
          selectedLocation.longitude
        );
      }
    } else {
      const allowedLocations = await pool.query(
        `
        SELECT DISTINCT
          l.*
        FROM company_locations l
        LEFT JOIN employee_location_map elm
          ON elm.location_id = l.id
         AND elm.employee_id = $2
        WHERE l.company_id = $1
          AND l.status = true
          AND (
            $3::boolean = true
            OR COALESCE(l.allow_all_employees, false) = true
            OR elm.employee_id IS NOT NULL
          )
        ORDER BY l.id ASC
        `,
        [companyId, employeeId, employee.allow_any_location === true]
      );

      if (!allowedLocations.rows.length) {
        return fail(
          res,
          400,
          'No allowed location found. Please assign location to this employee or enable Allow Any Location.'
        );
      }

      if (latitude && longitude) {
        let nearest = null;

        for (const location of allowedLocations.rows) {
          const d = haversine(
            latitude,
            longitude,
            location.latitude,
            location.longitude
          );

          if (d !== null && (!nearest || d < nearest.distance_m)) {
            nearest = {
              location,
              distance_m: d
            };
          }
        }

        if (nearest) {
          selectedLocation = nearest.location;
          locationId = nearest.location.id;
          distance_m = nearest.distance_m;
        }
      }

      if (!selectedLocation) {
        selectedLocation = allowedLocations.rows[0];
        locationId = selectedLocation.id;
        distance_m = null;
      }
    }

    const access = await employeeAllowedAt(companyId, employeeId, locationId);

    const isAllowed =
      typeof access === 'boolean'
        ? access
        : access && access.allowed === true;

    if (!isAllowed) {
      return fail(
        res,
        403,
        'Employee is not allowed to mark attendance from this location'
      );
    }

    if (
      GEOFENCE_REQUIRED &&
      distance_m !== null &&
      distance_m > Number(selectedLocation.geofence_radius_m || 100)
    ) {
      return fail(
        res,
        400,
        `Outside geofence. Distance ${Math.round(distance_m)}m`
      );
    }

    const live = LIVENESS_REQUIRED
      ? await aiCompareFrames(frames.length ? frames : [imageBase64])
      : {
          liveness_pass: true,
          movement_score: 1
        };

   if (LIVENESS_REQUIRED && !live.liveness_pass) {
  const movementScore = Number(
    live.movement_score ||
    live.movement ||
    live.face_movement ||
    0
  );

  const areaChangeScore = Number(
    live.area_change_score ||
    live.area_change ||
    live.size_change ||
    0
  );

  const frameCount = Array.isArray(frames) ? frames.length : 0;

  const softLivenessPass =
    frameCount >= 5 ||
    movementScore >= 0.003 ||
    areaChangeScore >= 0.003;

  if (!softLivenessPass) {
    return fail(
      res,
      400,
      'Liveness check failed. Please blink or slightly move your head and try again.',
      {
        liveness: live,
        movement_score: movementScore,
        area_change_score: areaChangeScore,
        frame_count: frameCount
      }
    );
  }
}

    const ai = await aiExtractSingle(imageBase64);

    if (!ai.success) {
      return fail(res, 400, ai.message || 'Face not detected');
    }

    const faces = await pool.query(
      `
      SELECT embedding
      FROM employee_faces
      WHERE employee_id = $1
        AND company_id = $2
      `,
      [employeeId, companyId]
    );

    if (!faces.rows.length) {
      return fail(res, 400, 'Employee face not enrolled');
    }

    let bestDistance = 999;

    for (const face of faces.rows) {
      const d = cosineDistance(ai.embedding, face.embedding);

      if (d < bestDistance) {
        bestDistance = d;
      }
    }

    if (bestDistance > MATCH_THRESHOLD) {
      return fail(res, 400, 'Face does not match', {
        distance: bestDistance,
        threshold: MATCH_THRESHOLD
      });
    }

    if (await duplicateRecently(employeeId)) {
      return fail(res, 400, 'Attendance already marked recently');
    }

    const punch = await nextPunchType(companyId, employeeId);

    await pool.query(
      `
      INSERT INTO attendance_logs (
        company_id,
        employee_id,
        location_id,
        punch_type,
        source,
        employee_name,
        match_score,
        liveness_pass,
        latitude,
        longitude,
        distance_m
      )
      VALUES ($1,$2,$3,$4,'self',$5,$6,$7,$8,$9,$10)
      `,
      [
        companyId,
        employeeId,
        locationId,
        punch,
        employee.name,
        bestDistance,
        true,
        latitude || null,
        longitude || null,
        distance_m
      ]
    );

    return ok(res, {
      message: `${punch} marked successfully`,
      punch_type: punch,
      distance: bestDistance,
      threshold: MATCH_THRESHOLD,
      location_id: locationId,
      location_name: selectedLocation?.name || '',
      distance_m,
      gps_accuracy: gps_accuracy || null
    });
  } catch (e) {
    console.error('Self Attendance Error:', e.message);

    return fail(res, 500, 'Server error during self attendance', {
      error: e.message
    });
  }
});

app.get('/api/reports/attendance', auth(), async (req, res) => {
  try {
    const companyId =
      req.user.role === 'super_admin'
        ? req.query.company_id
        : req.user.company_id;

    if (!companyId) {
      return fail(res, 400, 'Please select company first');
    }

    const from = req.query.from || new Date().toISOString().slice(0, 10);
    const to = req.query.to || from;

    const params = [companyId, from, to];

    let extra = '';

    if (req.user.role === 'employee') {
      if (!req.user.employee_id) {
        return fail(res, 400, 'Employee not found in login session');
      }

      params.push(req.user.employee_id);
      extra += ` AND a.employee_id = $${params.length}`;
    } else if (req.query.employee_id) {
      params.push(req.query.employee_id);
      extra += ` AND a.employee_id = $${params.length}`;
    }

    if (req.user.role === 'location_admin') {
      if (!req.user.location_id) {
        return fail(res, 400, 'Location not found in login session');
      }

      params.push(req.user.location_id);
      extra += ` AND a.location_id = $${params.length}`;
    } else if (req.query.location_id) {
      params.push(req.query.location_id);
      extra += ` AND a.location_id = $${params.length}`;
    }

    const result = await pool.query(
      `
      SELECT
        a.*,
        e.employee_code,
        e.name AS employee_master_name,
        l.name AS location_name,
        l.code AS location_code,
        c.name AS company_name
      FROM attendance_logs a
      LEFT JOIN employees e ON e.id = a.employee_id
      LEFT JOIN company_locations l ON l.id = a.location_id
      LEFT JOIN companies c ON c.id = a.company_id
      WHERE a.company_id = $1
        AND a.marked_at::date BETWEEN $2 AND $3
        ${extra}
      ORDER BY a.marked_at DESC
      `,
      params
    );

    ok(res, {
      rows: result.rows
    });
  } catch (error) {
    console.error('Attendance Report Error:', error.message);

    fail(res, 500, 'Unable to fetch attendance report', {
      error: error.message
    });
  }
});

app.post('/api/payroll/generate', auth(['company_admin','super_admin']), async (req,res)=>{
  const companyId = req.user.role==='super_admin' ? req.body.company_id : req.user.company_id;
  const { month, year } = req.body; const daysInMonth = new Date(year, month, 0).getDate();
  const emps = await pool.query(`SELECT * FROM employees WHERE company_id=$1 AND status=true`, [companyId]);
  const run = await pool.query(`INSERT INTO payroll_runs(company_id,month,year,generated_by,total_employees) VALUES($1,$2,$3,$4,$5) ON CONFLICT(company_id,month,year) DO UPDATE SET generated_by=EXCLUDED.generated_by,total_employees=EXCLUDED.total_employees,created_at=CURRENT_TIMESTAMP RETURNING *`, [companyId,month,year,req.user.id,emps.rows.length]);
  await pool.query(`DELETE FROM payroll_items WHERE payroll_run_id=$1`, [run.rows[0].id]);
  let total=0;
  for(const e of emps.rows){
    const att = await pool.query(`SELECT count(DISTINCT marked_at::date) present FROM attendance_logs WHERE company_id=$1 AND employee_id=$2 AND EXTRACT(MONTH FROM marked_at)=$3 AND EXTRACT(YEAR FROM marked_at)=$4 AND punch_type='IN'`, [companyId,e.id,month,year]);
    const present = Number(att.rows[0].present); const gross = Number(e.base_salary || 0); const net = Math.round((gross/daysInMonth)*present*100)/100; const deduction = gross-net; total+=net;
    await pool.query(`INSERT INTO payroll_items(payroll_run_id,employee_id,present_days,payable_days,gross_salary,deduction,net_salary) VALUES($1,$2,$3,$3,$4,$5,$6)`, [run.rows[0].id,e.id,present,gross,deduction,net]);
  }
  await pool.query(`UPDATE payroll_runs SET total_payable=$1 WHERE id=$2`, [total,run.rows[0].id]);
  ok(res,{message:'Payroll generated', payroll_run_id:run.rows[0].id, total_payable:total});
});
app.get('/api/payroll/:id', auth(), async(req,res)=>{
  const run = await pool.query(`SELECT * FROM payroll_runs WHERE id=$1`, [req.params.id]); if(!run.rows.length) return fail(res,404,'Payroll not found');
  if(!scopedCompany(req, run.rows[0].company_id)) return fail(res,403,'Access denied');
  const items = await pool.query(`SELECT pi.*, e.name, e.employee_code FROM payroll_items pi JOIN employees e ON e.id=pi.employee_id WHERE pi.payroll_run_id=$1`, [req.params.id]);
  ok(res,{run:run.rows[0], items:items.rows});
});
app.get('/api/super/masters/:type', auth(['super_admin']), async (req, res) => {
  try {
    const cfg = getMasterConfig(req.params.type);

    if (!cfg) {
      return fail(res, 400, 'Invalid master type');
    }

    const result = await pool.query(`
      SELECT *
      FROM ${cfg.table}
      ORDER BY id DESC
    `);

    ok(res, { items: result.rows });
  } catch (error) {
    console.error('Master List Error:', error.message);
    fail(res, 500, 'Master list failed', { error: error.message });
  }
});

app.post('/api/super/masters/:type', auth(['super_admin']), async (req, res) => {
  try {
    const cfg = getMasterConfig(req.params.type);

    if (!cfg) {
      return fail(res, 400, 'Invalid master type');
    }

    const fields = cfg.fields.filter((field) => req.body[field] !== undefined);
    const values = fields.map((field) => req.body[field]);
    const placeholders = fields.map((_, index) => `$${index + 1}`);

    if (!fields.includes('name')) {
      return fail(res, 400, 'Name is required');
    }

    const result = await pool.query(
      `
      INSERT INTO ${cfg.table} (${fields.join(', ')})
      VALUES (${placeholders.join(', ')})
      RETURNING *
      `,
      values
    );

    ok(res, {
      message: 'Master created successfully',
      item: result.rows[0]
    });
  } catch (error) {
    console.error('Master Create Error:', error.message);

    if (error.code === '23505') {
      return fail(res, 400, 'Duplicate record already exists');
    }

    fail(res, 500, 'Master create failed', { error: error.message });
  }
});

app.put('/api/super/masters/:type/:id', auth(['super_admin']), async (req, res) => {
  try {
    const cfg = getMasterConfig(req.params.type);

    if (!cfg) {
      return fail(res, 400, 'Invalid master type');
    }

    const fields = cfg.fields.filter((field) => req.body[field] !== undefined);

    if (!fields.length) {
      return fail(res, 400, 'No fields to update');
    }

    const values = fields.map((field) => req.body[field]);
    const setSql = fields.map((field, index) => `${field} = $${index + 1}`);

    values.push(req.params.id);

    const result = await pool.query(
      `
      UPDATE ${cfg.table}
      SET ${setSql.join(', ')},
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $${values.length}
      RETURNING *
      `,
      values
    );

    if (!result.rows.length) {
      return fail(res, 404, 'Master record not found');
    }

    ok(res, {
      message: 'Master updated successfully',
      item: result.rows[0]
    });
  } catch (error) {
    console.error('Master Update Error:', error.message);

    if (error.code === '23505') {
      return fail(res, 400, 'Duplicate record already exists');
    }

    fail(res, 500, 'Master update failed', { error: error.message });
  }
});

app.delete('/api/super/masters/:type/:id', auth(['super_admin']), async (req, res) => {
  try {
    const cfg = getMasterConfig(req.params.type);

    if (!cfg) {
      return fail(res, 400, 'Invalid master type');
    }

    const result = await pool.query(
      `
      DELETE FROM ${cfg.table}
      WHERE id = $1
      RETURNING id
      `,
      [req.params.id]
    );

    if (!result.rows.length) {
      return fail(res, 404, 'Master record not found');
    }

    ok(res, {
      message: 'Master deleted successfully'
    });
  } catch (error) {
    console.error('Master Delete Error:', error.message);

    if (error.code === '23503') {
      return fail(res, 400, 'This master is already used in records. Please deactivate instead of delete.');
    }

    fail(res, 500, 'Master delete failed', { error: error.message });
  }
});



// ================= ENTERPRISE EXTENSION MODULES =================
function requestMeta(req) {
  return {
    ip_address: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '',
    user_agent: req.headers['user-agent'] || ''
  };
}

async function writeAudit(req, moduleName, action, entityType = null, entityId = null, oldValue = null, newValue = null) {
  try {
    const meta = requestMeta(req);
    await pool.query(
      `INSERT INTO audit_logs(company_id,user_id,module_name,action,entity_type,entity_id,old_value,new_value,ip_address,user_agent)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [req.user?.company_id || req.body?.company_id || req.query?.company_id || null, req.user?.id || null, moduleName, action, entityType, entityId, oldValue, newValue, meta.ip_address, meta.user_agent]
    );
  } catch (e) {
    console.error('Audit Log Error:', e.message);
  }
}

function addCompanyFilter(req, baseParams, alias = '') {
  const prefix = alias ? `${alias}.` : '';
  if (req.user.role === 'super_admin') {
    if (req.query.company_id || req.body.company_id) {
      baseParams.push(req.query.company_id || req.body.company_id);
      return ` AND ${prefix}company_id = $${baseParams.length}`;
    }
    return '';
  }
  baseParams.push(req.user.company_id);
  return ` AND ${prefix}company_id = $${baseParams.length}`;
}

function requireAdmin(req, res) {
  if (!['super_admin','company_admin','location_admin'].includes(req.user.role)) {
    fail(res, 403, 'Access denied');
    return false;
  }
  return true;
}

function adminCompanyId(req) {
  return req.user.role === 'super_admin' ? (req.body.company_id || req.query.company_id) : req.user.company_id;
}

async function ensureEnterpriseSchema() {
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by INT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

    ALTER TABLE master_packages ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_packages ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_packages ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE master_departments ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_departments ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_departments ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE master_designations ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_designations ADD COLUMN IF NOT EXISTS level_no INT DEFAULT 0;
    ALTER TABLE master_designations ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_designations ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE master_employee_types ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_employee_types ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_employee_types ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    CREATE TABLE IF NOT EXISTS master_industry_types (
      id SERIAL PRIMARY KEY, name VARCHAR(150) UNIQUE NOT NULL, code VARCHAR(60), description TEXT, status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS master_company_sizes (
      id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, code VARCHAR(60), min_employees INT, max_employees INT, description TEXT, status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS master_leave_types (
      id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, code VARCHAR(60), paid_leave BOOLEAN DEFAULT TRUE, annual_quota NUMERIC(8,2) DEFAULT 0, description TEXT, status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS master_attendance_modes (
      id SERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, code VARCHAR(60), requires_face BOOLEAN DEFAULT TRUE, requires_location BOOLEAN DEFAULT TRUE, description TEXT, status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE master_industry_types ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_industry_types ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_industry_types ADD COLUMN IF NOT EXISTS status BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_industry_types ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE master_company_sizes ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_company_sizes ADD COLUMN IF NOT EXISTS min_employees INT;
    ALTER TABLE master_company_sizes ADD COLUMN IF NOT EXISTS max_employees INT;
    ALTER TABLE master_company_sizes ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_company_sizes ADD COLUMN IF NOT EXISTS status BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_company_sizes ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE master_leave_types ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_leave_types ADD COLUMN IF NOT EXISTS paid_leave BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_leave_types ADD COLUMN IF NOT EXISTS annual_quota NUMERIC(8,2) DEFAULT 0;
    ALTER TABLE master_leave_types ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_leave_types ADD COLUMN IF NOT EXISTS status BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_leave_types ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE master_attendance_modes ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_attendance_modes ADD COLUMN IF NOT EXISTS requires_face BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_attendance_modes ADD COLUMN IF NOT EXISTS requires_location BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_attendance_modes ADD COLUMN IF NOT EXISTS description TEXT;
    ALTER TABLE master_attendance_modes ADD COLUMN IF NOT EXISTS status BOOLEAN DEFAULT TRUE;
    ALTER TABLE master_attendance_modes ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE companies ADD COLUMN IF NOT EXISTS trial_start DATE;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS trial_end DATE;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS billing_cycle VARCHAR(30) DEFAULT 'monthly';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS auto_disable_after_expiry BOOLEAN DEFAULT TRUE;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS payment_status VARCHAR(30) DEFAULT 'pending';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS company_code VARCHAR(80);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS industry_type VARCHAR(150);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS company_size VARCHAR(120);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS website TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS gst_number VARCHAR(60);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS pan_number VARCHAR(60);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS cin_number VARCHAR(60);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS address_line1 TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS address_line2 TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS city VARCHAR(100);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS state VARCHAR(100);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS country VARCHAR(100) DEFAULT 'India';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS pincode VARCHAR(20);
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS primary_color VARCHAR(30) DEFAULT '#1976d2';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS timezone VARCHAR(80) DEFAULT 'Asia/Kolkata';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS geofence_required BOOLEAN DEFAULT TRUE;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS liveness_required BOOLEAN DEFAULT TRUE;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS duplicate_block_seconds INT DEFAULT 30;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS timezone VARCHAR(80) DEFAULT 'Asia/Kolkata';
    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS contact_person VARCHAR(160);
    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS contact_phone VARCHAR(30);
    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS kiosk_enabled BOOLEAN DEFAULT TRUE;
    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS self_attendance_enabled BOOLEAN DEFAULT TRUE;
    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS allow_all_employees BOOLEAN DEFAULT FALSE;
    ALTER TABLE company_locations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

    ALTER TABLE employees ADD COLUMN IF NOT EXISTS reporting_manager_id INT;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_status VARCHAR(40) DEFAULT 'active';
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_type VARCHAR(60);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS leave_balance NUMERIC(8,2) DEFAULT 0;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS self_attendance_allowed BOOLEAN DEFAULT TRUE;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS document_status VARCHAR(40) DEFAULT 'pending';
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS official_email VARCHAR(160);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS alternate_phone VARCHAR(30);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS gender VARCHAR(30);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS dob DATE;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS father_name VARCHAR(160);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS blood_group VARCHAR(20);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS probation_end_date DATE;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS reporting_manager VARCHAR(160);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_name VARCHAR(160);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_account_no VARCHAR(80);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS ifsc_code VARCHAR(40);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS pf_number VARCHAR(80);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS esi_number VARCHAR(80);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS pan_number VARCHAR(30);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS aadhaar_number VARCHAR(30);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS address_line1 TEXT;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS address_line2 TEXT;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS city VARCHAR(100);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS state VARCHAR(100);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS pincode VARCHAR(20);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS emergency_contact_name VARCHAR(160);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS emergency_contact_phone VARCHAR(30);
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS overtime_allowed BOOLEAN DEFAULT FALSE;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS late_mark_allowed BOOLEAN DEFAULT TRUE;
    ALTER TABLE employees ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS code VARCHAR(60);
    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS half_day_minutes INT DEFAULT 240;
    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS full_day_minutes INT DEFAULT 480;
    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS late_after_minutes INT DEFAULT 0;
    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS overtime_after_minutes INT DEFAULT 0;
    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS night_shift BOOLEAN DEFAULT FALSE;
    ALTER TABLE master_shifts ADD COLUMN IF NOT EXISTS weekly_off_days TEXT DEFAULT 'Sunday';

    CREATE TABLE IF NOT EXISTS role_permissions (
      id SERIAL PRIMARY KEY, role VARCHAR(60) NOT NULL, permission_key VARCHAR(120) NOT NULL,
      can_view BOOLEAN DEFAULT TRUE, can_create BOOLEAN DEFAULT FALSE, can_update BOOLEAN DEFAULT FALSE, can_delete BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(role, permission_key)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY, company_id INT, user_id INT, module_name VARCHAR(100), action VARCHAR(100),
      entity_type VARCHAR(100), entity_id INT, old_value JSONB, new_value JSONB,
      ip_address TEXT, user_agent TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS login_history (
      id SERIAL PRIMARY KEY, user_id INT, email VARCHAR(160), status VARCHAR(30), ip_address TEXT, user_agent TEXT,
      reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS employee_documents (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id) ON DELETE CASCADE,
      document_type VARCHAR(100), document_name VARCHAR(200), file_url TEXT, status VARCHAR(40) DEFAULT 'uploaded',
      uploaded_by INT, verified_by INT, verified_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS salary_structures (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id) ON DELETE CASCADE,
      basic NUMERIC(12,2) DEFAULT 0, hra NUMERIC(12,2) DEFAULT 0, allowance NUMERIC(12,2) DEFAULT 0,
      pf NUMERIC(12,2) DEFAULT 0, esic NUMERIC(12,2) DEFAULT 0, professional_tax NUMERIC(12,2) DEFAULT 0,
      tds NUMERIC(12,2) DEFAULT 0, loan_advance NUMERIC(12,2) DEFAULT 0, effective_from DATE DEFAULT CURRENT_DATE,
      status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS employee_leave_balances (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id) ON DELETE CASCADE,
      leave_type_id INT, opening_balance NUMERIC(8,2) DEFAULT 0, credited NUMERIC(8,2) DEFAULT 0,
      used NUMERIC(8,2) DEFAULT 0, adjusted NUMERIC(8,2) DEFAULT 0, year INT DEFAULT EXTRACT(YEAR FROM CURRENT_DATE),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(employee_id, leave_type_id, year)
    );

    CREATE TABLE IF NOT EXISTS attendance_regularizations (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), employee_id INT REFERENCES employees(id),
      attendance_date DATE NOT NULL, request_type VARCHAR(60), requested_in TIMESTAMP, requested_out TIMESTAMP,
      reason TEXT, attachment_url TEXT, status VARCHAR(30) DEFAULT 'pending', manager_approval_status VARCHAR(30) DEFAULT 'pending',
      hr_approval_status VARCHAR(30) DEFAULT 'pending', approved_by INT, approved_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS holidays (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), location_id INT REFERENCES company_locations(id),
      name VARCHAR(160) NOT NULL, holiday_date DATE NOT NULL, holiday_type VARCHAR(60) DEFAULT 'company',
      compensation_rule VARCHAR(100), status BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS payslips (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), payroll_run_id INT REFERENCES payroll_runs(id), employee_id INT REFERENCES employees(id),
      month INT, year INT, earnings JSONB DEFAULT '{}', deductions JSONB DEFAULT '{}', net_pay NUMERIC(12,2) DEFAULT 0,
      pdf_url TEXT, digitally_signed BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(employee_id, month, year)
    );

    CREATE TABLE IF NOT EXISTS approval_requests (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), module_name VARCHAR(100), request_type VARCHAR(100),
      entity_id INT, requested_by INT, level_no INT DEFAULT 1, approver_id INT, status VARCHAR(30) DEFAULT 'pending',
      remarks TEXT, payload JSONB DEFAULT '{}', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, action_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY, company_id INT, user_id INT, channel VARCHAR(40) DEFAULT 'in_app', title VARCHAR(200),
      message TEXT, status VARCHAR(40) DEFAULT 'unread', event_key VARCHAR(100), payload JSONB DEFAULT '{}', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS kiosk_devices (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), location_id INT REFERENCES company_locations(id),
      device_code VARCHAR(80) UNIQUE NOT NULL, device_name VARCHAR(160), browser_fingerprint TEXT,
      kiosk_lock_mode BOOLEAN DEFAULT TRUE, status BOOLEAN DEFAULT TRUE, last_online_at TIMESTAMP,
      camera_health_status VARCHAR(40) DEFAULT 'unknown', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS company_settings (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id) UNIQUE,
      attendance_policy JSONB DEFAULT '{}', shift_policy JSONB DEFAULT '{}', leave_policy JSONB DEFAULT '{}', payroll_policy JSONB DEFAULT '{}',
      geofence_policy JSONB DEFAULT '{}', notification_settings JSONB DEFAULT '{}', face_match_threshold NUMERIC(6,4) DEFAULT 0.4200,
      liveness_required BOOLEAN DEFAULT TRUE, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS bulk_upload_jobs (
      id SERIAL PRIMARY KEY, company_id INT REFERENCES companies(id), upload_type VARCHAR(80), file_name VARCHAR(200),
      total_rows INT DEFAULT 0, success_rows INT DEFAULT 0, failed_rows INT DEFAULT 0, error_report_url TEXT,
      status VARCHAR(40) DEFAULT 'uploaded', uploaded_by INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_audit_company_time ON audit_logs(company_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_login_history_time ON login_history(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_regularization_company_status ON attendance_regularizations(company_id, status);
    CREATE INDEX IF NOT EXISTS idx_notifications_user_status ON notifications(user_id, status);
  `);

  await pool.query(`
    INSERT INTO master_industry_types(name, code, description) VALUES
      ('Information Technology','IT','Software and IT services'),
      ('Manufacturing','MFG','Manufacturing and production'),
      ('Healthcare','HEALTH','Healthcare organizations'),
      ('Education','EDU','Schools, colleges and training'),
      ('Retail','RETAIL','Retail and outlets'),
      ('Government','GOV','Government and public sector'),
      ('Security Services','SECURITY','Security and facility management'),
      ('Other','OTHER','Other industry')
    ON CONFLICT(name) DO NOTHING;

    INSERT INTO master_company_sizes(name, code, min_employees, max_employees, description) VALUES
      ('1-10 Employees','1_10',1,10,'Small team'),
      ('11-50 Employees','11_50',11,50,'Small business'),
      ('51-200 Employees','51_200',51,200,'Medium business'),
      ('201-500 Employees','201_500',201,500,'Large business'),
      ('501-1000 Employees','501_1000',501,1000,'Enterprise'),
      ('1000+ Employees','1000_PLUS',1001,NULL,'Large enterprise')
    ON CONFLICT(name) DO NOTHING;

    INSERT INTO master_leave_types(name, code, paid_leave, annual_quota, description) VALUES
      ('Casual Leave','CL',true,12,'Casual leave'),
      ('Sick Leave','SL',true,12,'Sick leave'),
      ('Earned Leave','EL',true,15,'Earned leave'),
      ('Loss of Pay','LOP',false,0,'Unpaid leave')
    ON CONFLICT(name) DO NOTHING;

    INSERT INTO master_attendance_modes(name, code, requires_face, requires_location, description) VALUES
      ('Face Attendance','FACE',true,true,'Face based attendance'),
      ('Self Attendance','SELF',true,true,'Employee self attendance'),
      ('Kiosk Attendance','KIOSK',true,true,'Kiosk based attendance'),
      ('Manual Attendance','MANUAL',false,false,'Manual attendance')
    ON CONFLICT(name) DO NOTHING;
  `);

  await pool.query(`
    INSERT INTO role_permissions(role,permission_key,can_view,can_create,can_update,can_delete) VALUES
      ('super_admin','companies',true,true,true,true),('super_admin','users',true,true,true,true),('super_admin','reports',true,true,true,true),('super_admin','settings',true,true,true,true),
      ('company_admin','users',true,true,true,false),('company_admin','employees',true,true,true,true),('company_admin','attendance',true,true,true,false),('company_admin','reports',true,true,true,false),('company_admin','payroll',true,true,true,false),
      ('location_admin','attendance',true,true,true,false),('location_admin','reports',true,false,false,false),
      ('employee','self_attendance',true,true,false,false),('employee','reports',true,false,false,false),('employee','payslips',true,false,false,false)
    ON CONFLICT(role,permission_key) DO NOTHING;
  `);
}

app.post('/api/auth/refresh', auth(), async (req, res) => {
  const r = await pool.query(`SELECT u.*, c.name company_name, c.logo_url FROM users u LEFT JOIN companies c ON c.id=u.company_id WHERE u.id=$1 AND u.status=true`, [req.user.id]);
  if (!r.rows.length) return fail(res, 401, 'User account is not active');
  const user = r.rows[0]; delete user.password_md5;
  ok(res, { token: signToken(user), user });
});

app.post('/api/auth/change-password', auth(), async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return fail(res, 400, 'Current password and new password are required');
  if (String(new_password).length < 6) return fail(res, 400, 'New password must be at least 6 characters');
  const r = await pool.query(`SELECT id FROM users WHERE id=$1 AND password_md5=$2`, [req.user.id, md5(current_password)]);
  if (!r.rows.length) return fail(res, 400, 'Current password is incorrect');
  await pool.query(`UPDATE users SET password_md5=$2, updated_at=NOW() WHERE id=$1`, [req.user.id, md5(new_password)]);
  await writeAudit(req, 'security', 'change_password', 'users', req.user.id, null, null);
  ok(res, { message: 'Password changed successfully' });
});

app.get('/api/permissions', auth(), async (req, res) => {
  const r = await pool.query(`SELECT * FROM role_permissions ORDER BY role, permission_key`);
  ok(res, { rows: r.rows });
});

app.put('/api/permissions/:id', auth(['super_admin']), async (req, res) => {
  const { can_view, can_create, can_update, can_delete } = req.body;
  const r = await pool.query(
    `UPDATE role_permissions SET can_view=$2, can_create=$3, can_update=$4, can_delete=$5 WHERE id=$1 RETURNING *`,
    [req.params.id, !!can_view, !!can_create, !!can_update, !!can_delete]
  );
  if (!r.rows.length) return fail(res, 404, 'Permission not found');
  await writeAudit(req, 'permissions', 'update', 'role_permissions', req.params.id, null, r.rows[0]);
  ok(res, { item: r.rows[0], message: 'Permission updated successfully' });
});

app.get('/api/admin/users', auth(['super_admin','company_admin']), async (req, res) => {
  const params=[]; let where='WHERE 1=1';
  where += addCompanyFilter(req, params, 'u');
  const r = await pool.query(`SELECT u.id,u.company_id,u.employee_id,u.location_id,u.name,u.email,u.phone,u.role,u.status,u.last_login_at,u.failed_login_attempts,u.created_at,c.name company_name,l.name location_name FROM users u LEFT JOIN companies c ON c.id=u.company_id LEFT JOIN company_locations l ON l.id=u.location_id ${where} ORDER BY u.id DESC`, params);
  ok(res, { users: r.rows });
});

app.post('/api/admin/users', auth(['super_admin','company_admin']), async (req, res) => {
  const companyId = adminCompanyId(req);
  if (req.user.role !== 'super_admin' && !companyId) return fail(res, 400, 'Company is required');
  const { name, email, phone, role, employee_id, location_id, password } = req.body;
  if (!name || !email || !role) return fail(res, 400, 'Name, email and role are required');
  const defaultPassword = password || 'Password@123';
  const r = await pool.query(`INSERT INTO users(company_id,employee_id,location_id,name,email,phone,password_md5,role,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,$9) RETURNING id,name,email,role,status,company_id,location_id`, [companyId || null, employee_id || null, location_id || null, name, email, phone || null, md5(defaultPassword), role, req.user.id]);
  await writeAudit(req, 'users', 'create', 'users', r.rows[0].id, null, r.rows[0]);
  ok(res, { user: r.rows[0], message: 'User created successfully', temporary_password: defaultPassword });
});

app.put('/api/admin/users/:id', auth(['super_admin','company_admin']), async (req, res) => {
  const companyId = adminCompanyId(req);
  const { name, phone, role, employee_id, location_id, status } = req.body;
  const params=[req.params.id, name, phone || null, role, employee_id || null, location_id || null, status !== false];
  let where='id=$1';
  if(req.user.role !== 'super_admin') { params.push(companyId); where += ` AND company_id=$${params.length}`; }
  const r = await pool.query(`UPDATE users SET name=COALESCE($2,name), phone=$3, role=COALESCE($4,role), employee_id=$5, location_id=$6, status=$7, updated_at=NOW() WHERE ${where} RETURNING id,name,email,role,status,company_id,location_id`, params);
  if(!r.rows.length) return fail(res,404,'User not found');
  await writeAudit(req, 'users', 'update', 'users', req.params.id, null, r.rows[0]);
  ok(res,{user:r.rows[0],message:'User updated successfully'});
});

app.post('/api/admin/users/:id/reset-password', auth(['super_admin','company_admin']), async(req,res)=>{
  const newPassword = req.body.password || 'Password@123';
  const params=[req.params.id, md5(newPassword)]; let where='id=$1';
  if(req.user.role !== 'super_admin') { params.push(req.user.company_id); where += ` AND company_id=$${params.length}`; }
  const r = await pool.query(`UPDATE users SET password_md5=$2, failed_login_attempts=0, locked_until=NULL, updated_at=NOW() WHERE ${where} RETURNING id,email`, params);
  if(!r.rows.length) return fail(res,404,'User not found');
  await writeAudit(req,'users','reset_password','users',req.params.id,null,null);
  ok(res,{message:'Password reset successfully', temporary_password:newPassword});
});

app.get('/api/security/audit-logs', auth(['super_admin','company_admin']), async(req,res)=>{
  const params=[]; let where='WHERE 1=1';
  where += addCompanyFilter(req, params, 'a');
  const r = await pool.query(`SELECT a.*, u.name user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ${where} ORDER BY a.created_at DESC LIMIT 300`, params);
  ok(res,{rows:r.rows});
});

app.get('/api/security/login-history', auth(['super_admin','company_admin']), async(req,res)=>{
  const params=[]; let where='WHERE 1=1';
  if(req.user.role !== 'super_admin') { params.push(req.user.company_id); where += ` AND u.company_id=$${params.length}`; }
  const r = await pool.query(`SELECT lh.*, u.name user_name, u.role, u.company_id FROM login_history lh LEFT JOIN users u ON u.id=lh.user_id ${where} ORDER BY lh.created_at DESC LIMIT 300`, params);
  ok(res,{rows:r.rows});
});

app.get('/api/settings/company', auth(['super_admin','company_admin']), async(req,res)=>{
  const companyId = adminCompanyId(req);
  if(!companyId) return fail(res,400,'Company is required');
  await pool.query(`INSERT INTO company_settings(company_id) VALUES($1) ON CONFLICT(company_id) DO NOTHING`, [companyId]);
  const r = await pool.query(`SELECT * FROM company_settings WHERE company_id=$1`, [companyId]);
  ok(res,{settings:r.rows[0]});
});

app.put('/api/settings/company', auth(['super_admin','company_admin']), async(req,res)=>{
  const companyId = adminCompanyId(req);
  if(!companyId) return fail(res,400,'Company is required');
  const b=req.body;
  await pool.query(`INSERT INTO company_settings(company_id) VALUES($1) ON CONFLICT(company_id) DO NOTHING`, [companyId]);
  const r=await pool.query(`UPDATE company_settings SET attendance_policy=$2, shift_policy=$3, leave_policy=$4, payroll_policy=$5, geofence_policy=$6, notification_settings=$7, face_match_threshold=$8, liveness_required=$9, updated_at=NOW() WHERE company_id=$1 RETURNING *`, [companyId, b.attendance_policy||{}, b.shift_policy||{}, b.leave_policy||{}, b.payroll_policy||{}, b.geofence_policy||{}, b.notification_settings||{}, b.face_match_threshold||MATCH_THRESHOLD, b.liveness_required!==false]);
  await writeAudit(req,'settings','update','company_settings',companyId,null,r.rows[0]);
  ok(res,{settings:r.rows[0], message:'Settings updated successfully'});
});

function crudRoutes(path, table, label, allowedRoles=['super_admin','company_admin']) {
  app.get(`/api/${path}`, auth(), async(req,res)=>{
    if(req.user.role==='employee' && !['leave-requests','regularizations','payslips','notifications'].includes(path)) return fail(res,403,'Access denied');
    const params=[]; let where='WHERE 1=1';
    if(table.includes('company_id')) {}
    where += addCompanyFilter(req, params);
    if(req.user.role==='employee' && ['leave_requests','attendance_regularizations','payslips'].includes(table)) { params.push(req.user.employee_id); where += ` AND employee_id=$${params.length}`; }
    const r=await pool.query(`SELECT * FROM ${table} ${where} ORDER BY id DESC LIMIT 500`, params);
    ok(res,{rows:r.rows});
  });
}

app.get('/api/shifts', auth(['super_admin','company_admin','location_admin']), async(req,res)=>{
  const r=await pool.query(`SELECT * FROM master_shifts ORDER BY id DESC`);
  ok(res,{rows:r.rows});
});
app.post('/api/shifts', auth(['super_admin','company_admin']), async(req,res)=>{
  const b=req.body; if(!b.name) return fail(res,400,'Shift name is required');
  const r=await pool.query(`INSERT INTO master_shifts(name,code,start_time,end_time,grace_minutes,half_day_minutes,full_day_minutes,late_after_minutes,overtime_after_minutes,night_shift,weekly_off_days,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) RETURNING *`, [b.name,b.code||null,b.start_time||null,b.end_time||null,b.grace_minutes||0,b.half_day_minutes||240,b.full_day_minutes||480,b.late_after_minutes||0,b.overtime_after_minutes||0,!!b.night_shift,b.weekly_off_days||'Sunday']);
  await writeAudit(req,'shifts','create','master_shifts',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Shift created successfully'});
});
app.put('/api/shifts/:id', auth(['super_admin','company_admin']), async(req,res)=>{
  const b=req.body; const r=await pool.query(`UPDATE master_shifts SET name=COALESCE($2,name), code=$3, start_time=$4, end_time=$5, grace_minutes=$6, half_day_minutes=$7, full_day_minutes=$8, late_after_minutes=$9, overtime_after_minutes=$10, night_shift=$11, weekly_off_days=$12, status=$13 WHERE id=$1 RETURNING *`, [req.params.id,b.name,b.code||null,b.start_time||null,b.end_time||null,b.grace_minutes||0,b.half_day_minutes||240,b.full_day_minutes||480,b.late_after_minutes||0,b.overtime_after_minutes||0,!!b.night_shift,b.weekly_off_days||'Sunday',b.status!==false]);
  if(!r.rows.length) return fail(res,404,'Shift not found'); await writeAudit(req,'shifts','update','master_shifts',req.params.id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Shift updated successfully'});
});

app.get('/api/leave-types', auth(['super_admin','company_admin','employee']), async(req,res)=>{ const r=await pool.query(`SELECT * FROM master_leave_types ORDER BY id DESC`); ok(res,{rows:r.rows}); });
app.post('/api/leave-types', auth(['super_admin','company_admin']), async(req,res)=>{ const b=req.body; if(!b.name) return fail(res,400,'Leave type name is required'); const r=await pool.query(`INSERT INTO master_leave_types(name,code,paid_leave,annual_quota,description,status) VALUES($1,$2,$3,$4,$5,true) RETURNING *`, [b.name,b.code||null,b.paid_leave!==false,b.annual_quota||0,b.description||null]); await writeAudit(req,'leave_types','create','master_leave_types',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Leave type created successfully'}); });

app.get('/api/leave-requests', auth(), async (req, res) => {
  try {
    const params = [];
    let where = 'WHERE 1=1';

    // Important: use lr alias to avoid ambiguous company_id error
    where += addCompanyFilter(req, params, 'lr');

    if (req.user.role === 'employee') {
      params.push(req.user.employee_id);
      where += ` AND lr.employee_id = $${params.length}`;
    }

    if (req.user.role === 'location_admin' && req.user.location_id) {
      params.push(req.user.location_id);
      where += ` AND e.location_id = $${params.length}`;
    }

    const result = await pool.query(
      `
      SELECT
        lr.*,
        e.name AS employee_name,
        e.employee_code
      FROM leave_requests lr
      LEFT JOIN employees e ON e.id = lr.employee_id
      ${where}
      ORDER BY lr.id DESC
      `,
      params
    );

    ok(res, {
      rows: result.rows
    });
  } catch (error) {
    console.error('Leave Requests Error:', error.message);

    fail(res, 500, 'Unable to fetch leave requests', {
      error: error.message
    });
  }
});
app.post('/api/leave-requests', auth(), async(req,res)=>{
  const companyId=adminCompanyId(req) || req.user.company_id; const employeeId=req.user.role==='employee'?req.user.employee_id:req.body.employee_id;
  const b=req.body; if(!employeeId || !b.from_date || !b.to_date) return fail(res,400,'Employee and date range are required');
  const r=await pool.query(`INSERT INTO leave_requests(company_id,employee_id,leave_type,from_date,to_date,reason,status) VALUES($1,$2,$3,$4,$5,$6,'pending') RETURNING *`,[companyId,employeeId,b.leave_type||b.leave_type_id||'Leave',b.from_date,b.to_date,b.reason||null]);
  await writeAudit(req,'leave_requests','create','leave_requests',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Leave request submitted successfully'});
});
app.put('/api/leave-requests/:id/status', auth(['super_admin','company_admin','location_admin']), async(req,res)=>{
  const r=await pool.query(`UPDATE leave_requests SET status=$2, approved_by=$3 WHERE id=$1 RETURNING *`,[req.params.id,req.body.status||'approved',req.user.id]); if(!r.rows.length) return fail(res,404,'Leave request not found'); await writeAudit(req,'leave_requests','status_update','leave_requests',req.params.id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Leave request updated successfully'});
});

app.get('/api/regularizations', auth(), async(req,res)=>{
  const params=[]; let where='WHERE 1=1'; where += addCompanyFilter(req,params,'ar'); if(req.user.role==='employee'){params.push(req.user.employee_id); where+=` AND ar.employee_id=$${params.length}`;}
  const r=await pool.query(`SELECT ar.*, e.name employee_name FROM attendance_regularizations ar LEFT JOIN employees e ON e.id=ar.employee_id ${where} ORDER BY ar.id DESC`,params); ok(res,{rows:r.rows});
});
app.post('/api/regularizations', auth(), async(req,res)=>{
  const companyId=adminCompanyId(req)||req.user.company_id; const employeeId=req.user.role==='employee'?req.user.employee_id:req.body.employee_id; const b=req.body;
  if(!employeeId || !b.attendance_date || !b.request_type) return fail(res,400,'Employee, date and request type are required');
  const r=await pool.query(`INSERT INTO attendance_regularizations(company_id,employee_id,attendance_date,request_type,requested_in,requested_out,reason,attachment_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[companyId,employeeId,b.attendance_date,b.request_type,b.requested_in||null,b.requested_out||null,b.reason||null,b.attachment_url||null]);
  await writeAudit(req,'regularization','create','attendance_regularizations',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Regularization request submitted successfully'});
});
app.put('/api/regularizations/:id/status', auth(['super_admin','company_admin','location_admin']), async(req,res)=>{ const b=req.body; const r=await pool.query(`UPDATE attendance_regularizations SET status=$2, manager_approval_status=$2, hr_approval_status=$2, approved_by=$3, approved_at=NOW() WHERE id=$1 RETURNING *`,[req.params.id,b.status||'approved',req.user.id]); if(!r.rows.length)return fail(res,404,'Request not found'); await writeAudit(req,'regularization','status_update','attendance_regularizations',req.params.id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Regularization updated successfully'}); });

app.get('/api/holidays', auth(['super_admin','company_admin','location_admin','employee']), async(req,res)=>{ const params=[]; let where='WHERE 1=1'; where+=addCompanyFilter(req,params); const r=await pool.query(`SELECT * FROM holidays ${where} ORDER BY holiday_date DESC`,params); ok(res,{rows:r.rows}); });
app.post('/api/holidays', auth(['super_admin','company_admin']), async(req,res)=>{ const companyId=adminCompanyId(req); const b=req.body; if(!companyId || !b.name || !b.holiday_date) return fail(res,400,'Company, holiday name and date are required'); const r=await pool.query(`INSERT INTO holidays(company_id,location_id,name,holiday_date,holiday_type,compensation_rule,status) VALUES($1,$2,$3,$4,$5,$6,true) RETURNING *`,[companyId,b.location_id||null,b.name,b.holiday_date,b.holiday_type||'company',b.compensation_rule||null]); await writeAudit(req,'holidays','create','holidays',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Holiday created successfully'}); });

app.get('/api/devices', auth(['super_admin','company_admin','location_admin']), async(req,res)=>{ const params=[]; let where='WHERE 1=1'; where+=addCompanyFilter(req,params); if(req.user.role==='location_admin'){params.push(req.user.location_id); where+=` AND location_id=$${params.length}`;} const r=await pool.query(`SELECT * FROM kiosk_devices ${where} ORDER BY id DESC`,params); ok(res,{rows:r.rows}); });
app.post('/api/devices', auth(['super_admin','company_admin']), async(req,res)=>{ const companyId=adminCompanyId(req); const b=req.body; if(!companyId || !b.location_id || !b.device_code) return fail(res,400,'Company, location and device code are required'); const r=await pool.query(`INSERT INTO kiosk_devices(company_id,location_id,device_code,device_name,browser_fingerprint,kiosk_lock_mode,camera_health_status,status) VALUES($1,$2,$3,$4,$5,$6,$7,true) RETURNING *`,[companyId,b.location_id,b.device_code,b.device_name||null,b.browser_fingerprint||null,b.kiosk_lock_mode!==false,b.camera_health_status||'unknown']); await writeAudit(req,'devices','create','kiosk_devices',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Device registered successfully'}); });

app.get('/api/payslips', auth(), async(req,res)=>{ const params=[]; let where='WHERE 1=1'; where+=addCompanyFilter(req,params); if(req.user.role==='employee'){params.push(req.user.employee_id); where += ` AND employee_id=$${params.length}`;} const r=await pool.query(`SELECT * FROM payslips ${where} ORDER BY year DESC, month DESC`,params); ok(res,{rows:r.rows}); });

app.get('/api/approvals', auth(['super_admin','company_admin','location_admin']), async(req,res)=>{ const params=[]; let where='WHERE 1=1'; where+=addCompanyFilter(req,params); const r=await pool.query(`SELECT * FROM approval_requests ${where} ORDER BY id DESC`,params); ok(res,{rows:r.rows}); });
app.put('/api/approvals/:id/status', auth(['super_admin','company_admin','location_admin']), async(req,res)=>{ const r=await pool.query(`UPDATE approval_requests SET status=$2, remarks=$3, approver_id=$4, action_at=NOW() WHERE id=$1 RETURNING *`,[req.params.id,req.body.status||'approved',req.body.remarks||null,req.user.id]); if(!r.rows.length)return fail(res,404,'Approval request not found'); await writeAudit(req,'approvals','status_update','approval_requests',req.params.id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Approval updated successfully'}); });

app.get('/api/notifications', auth(), async(req,res)=>{ const params=[req.user.id]; let where='WHERE (user_id=$1 OR user_id IS NULL)'; if(req.user.role!=='super_admin'){params.push(req.user.company_id); where += ` AND (company_id=$${params.length} OR company_id IS NULL)`;} const r=await pool.query(`SELECT * FROM notifications ${where} ORDER BY id DESC LIMIT 200`,params); ok(res,{rows:r.rows}); });

app.get('/api/bulk/jobs', auth(['super_admin','company_admin']), async(req,res)=>{ const params=[]; let where='WHERE 1=1'; where+=addCompanyFilter(req,params); const r=await pool.query(`SELECT * FROM bulk_upload_jobs ${where} ORDER BY id DESC`,params); ok(res,{rows:r.rows}); });
app.post('/api/bulk/jobs', auth(['super_admin','company_admin']), async(req,res)=>{ const companyId=adminCompanyId(req); const b=req.body; if(!companyId || !b.upload_type) return fail(res,400,'Company and upload type are required'); const r=await pool.query(`INSERT INTO bulk_upload_jobs(company_id,upload_type,file_name,total_rows,success_rows,failed_rows,status,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[companyId,b.upload_type,b.file_name||null,b.total_rows||0,b.success_rows||0,b.failed_rows||0,b.status||'uploaded',req.user.id]); await writeAudit(req,'bulk_upload','create','bulk_upload_jobs',r.rows[0].id,null,r.rows[0]); ok(res,{item:r.rows[0],message:'Bulk upload job recorded successfully'}); });

app.get('/api/enterprise/summary', auth(), async(req,res)=>{
  const companyId=adminCompanyId(req)||req.user.company_id;
  const out={};
  if(companyId){
    const q=async(sql,params)=>{const r=await pool.query(sql,params); return Number(r.rows[0]?.count||0);};
    out.users=await q('SELECT COUNT(*) FROM users WHERE company_id=$1',[companyId]);
    out.employees=await q('SELECT COUNT(*) FROM employees WHERE company_id=$1',[companyId]);
    out.locations=await q('SELECT COUNT(*) FROM company_locations WHERE company_id=$1',[companyId]);
    out.devices=await q('SELECT COUNT(*) FROM kiosk_devices WHERE company_id=$1',[companyId]);
    out.pending_leaves=await q("SELECT COUNT(*) FROM leave_requests WHERE company_id=$1 AND status='pending'",[companyId]);
    out.pending_regularizations=await q("SELECT COUNT(*) FROM attendance_regularizations WHERE company_id=$1 AND status='pending'",[companyId]);
  }
  ok(res,{summary:out});
});

async function startServer() {
  await ensureSchema();
  await ensureEnterpriseSchema();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Enterprise backend running on ${PORT}`);
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error('Backend Startup Error:', error);
    process.exit(1);
  });
}

module.exports = app;