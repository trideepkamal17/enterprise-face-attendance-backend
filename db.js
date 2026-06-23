const { Pool } = require('pg');
require('dotenv').config();

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required. Configure backend/.env before starting the server.');
}

const useSsl = process.env.DATABASE_SSL === '1';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX || 20),
  idleTimeoutMillis: Number(process.env.DB_IDLE_TIMEOUT_MS || 30000),
  connectionTimeoutMillis: Number(process.env.DB_CONNECTION_TIMEOUT_MS || 10000),
  ssl: useSsl ? { rejectUnauthorized: false } : false,
  application_name: process.env.DB_APPLICATION_NAME || 'enterprise-face-attendance'
});

pool.on('error', (error) => {
  console.error('PostgreSQL Pool Error:', error.message);
});

module.exports = pool;
