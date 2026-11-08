import { pool } from './db.js';

export function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || '0.0.0.0';
}

const isPrivate = (ip) =>
  ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' ||
  ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.');

export async function lookupIpInfo(ip) {
  // 1. Handle local testing
  if (isPrivate(ip)) {
    return { isp: 'Localhost / Private Network', country: 'Local', city: 'Local' };
  }
  
  try {
    // 2. Ask the API for the data (we don't strictly need lat/lon here because the frontend map will get it from the city name, but it's fine to keep it)
    const url = `http://ip-api.com/json/${ip}?fields=status,country,city,isp`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(url, { signal: ctrl.signal });
    clearTimeout(t);
    const data = await res.json();
    
    return {
      isp: data.isp || 'Unknown',
      country: data.country || 'Unknown',
      city: data.city || 'Unknown',
    };
  } catch {
    return { isp: 'Lookup failed', country: '-', city: '-' };
  }
}

export async function logAttempt(username, ip, success, reason) {
  const info = await lookupIpInfo(ip);
  
  // 3. Save to database (only saving isp, country, city as per your database schema)
  await pool.query(
    `INSERT INTO login_attempts
       (username, ip_address, isp, country, city, success, reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [username, ip, info.isp, info.country, info.city, success, reason]
  );
}