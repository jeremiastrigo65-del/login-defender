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
  if (isPrivate(ip)) {
    return { isp: 'Localhost / Private Network', country: 'Local', city: 'Local' };
  }
  try {
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
  await pool.query(
    `INSERT INTO login_attempts
       (username, ip_address, isp, country, city, success, reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [username, ip, info.isp, info.country, info.city, success, reason]
  );
}