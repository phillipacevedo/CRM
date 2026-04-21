#!/usr/bin/env node
// Usage: node reset-password.js <email> <new-password>
// Resets a user's password in the local CRM database.
//
// To reset on Render, open Dashboard → your service → Shell and run the same command.

const bcrypt   = require('bcryptjs');
const path     = require('path');
const Database = require('better-sqlite3');

const [,, email, newPassword] = process.argv;

if (!email || !newPassword) {
  console.error('Usage: node reset-password.js <email> <new-password>');
  process.exit(1);
}

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'crm.db');
const db = new Database(DB_PATH);

const user = db.prepare('SELECT email, name FROM users WHERE email = ?').get(email.toLowerCase().trim());
if (!user) {
  console.error(`No account found for: ${email}`);
  console.log('\nExisting accounts:');
  db.prepare('SELECT email, name FROM users').all().forEach(u => console.log(' -', u.email, '/', u.name));
  process.exit(1);
}

const hash = bcrypt.hashSync(newPassword, 10);
db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(hash, user.email);
console.log(`Password reset for ${user.name} (${user.email}). You can now log in with the new password.`);
