
//local

// const { Pool } = require('pg');
// require('dotenv').config();
// const pool = new Pool({ connectionString: process.env.DATABASE_URL });
// module.exports = pool;


// Production
const { Pool } = require('pg');
require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
});

module.exports = pool;