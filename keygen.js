const crypto = require('crypto');
const key = crypto.randomBytes(32); // 256 bits key
const iv = crypto.randomBytes(16);  // Initialization vector.
console.log("key: " + key.toString('hex'));
console.log("iv: " + iv.toString('hex'));