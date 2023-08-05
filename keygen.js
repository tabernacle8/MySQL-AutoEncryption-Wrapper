const crypto = require('crypto');
const key = crypto.randomBytes(32); // 256 bits key
console.log("key: " + key.toString('hex'));