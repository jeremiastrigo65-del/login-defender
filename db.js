import pg from 'pg';
const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Neon requires SSL
});

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role          VARCHAR(10) DEFAULT 'user',
      failed_attempts INT DEFAULT 0,
      locked_until  TIMESTAMPTZ,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id           SERIAL PRIMARY KEY,
      username     VARCHAR(50),
      ip_address   VARCHAR(45),
      isp          VARCHAR(150),
      country      VARCHAR(100),
      city         VARCHAR(100),
      success      BOOLEAN,
      reason       VARCHAR(100),
      attempted_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Seed admin + test user if missing
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS c FROM users WHERE role='admin'`
  );
  if (rows[0].c === 0) {
    const bcrypt = (await import('bcryptjs')).default;
    await pool.query(
      `INSERT INTO users (username, password_hash, role) VALUES ($1,$2,'admin')`,
      ['admin', bcrypt.hashSync('admin123', 10)]
    );
    await pool.query(
      `INSERT INTO users (username, password_hash, role) VALUES ($1,$2,'user')`,
      ['testuser', bcrypt.hashSync('user123', 10)]
    );
  }
}