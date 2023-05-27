const mysql = require("mysql");
const crypto = require("crypto");
const config = require('./config.json');


const algorithm = "aes-256-cbc";
const key = Buffer.from(
    config.encryption.key,
    "hex"
);
const iv = Buffer.from(config.encryption.iv, "hex");

// Add this function to your file
function encrypt(text) {
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return {
        iv: iv.toString("hex"),
        encryptedData: encrypted.toString("hex")
    };
}

// Add this function to your file
function decrypt(encryptedText) {
    if(encryptedText == null) return null;
    if(!encryptedText.includes(config.settings.securedBuffer)) return encryptedText;
    encryptedText = encryptedText.replace(config.settings.securedBuffer, "");
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
    let encryptedBuffer = Buffer.from(encryptedText, 'hex');
    let decrypted = decipher.update(encryptedBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}


exports.query = function (query, params, callback) {

    var database = mysql.createConnection({
        host: config.database.host,
        user: config.database.user,
        password: config.database.password,
        database: config.database.database,
    });

    //Encrypt each parameter and then pass it to the query
    for (var i = 0; i < params.length; i++) {
        if(params[i].includes(config.settings.securedBuffer)){
            callback("Query failed: parameter " + i + " is already encrypted", null);
            database.end();
            return;
        }
        params[i] = config.settings.securedBuffer+(encrypt(params[i].toString()).encryptedData);
    }

    //If any params are over 500 characters, log and stop the query
    for (var i = 0; i < params.length; i++) {
        if (params[i].length > wrapper.settings.maxTableLength) {
            callback("Query failed: parameter " + i + " is too long", null);
            database.end();
            return;
        }
    }

    //Execute the query
    if (params.length == 0) {
        database.query(query, [], function (err, result) {
            if (err) {
                callback(err, null);
            } else {
                if (result.length == 0) {
                    callback(null, null);
                    database.end();
                    return;
                }
                for (var i = 0; i < result.length; i++) {
                    for (var key in result[i]) {
                        result[i][key] = decrypt(result[i][key]);
                    }
                }
                callback(null, result);
                database.end();
            }
        });
    } 
    
    else {
        database.query(query, params, function (err, result) {
            if (err) {
                callback(err, null);
                database.end();
            } else {
                for (var i = 0; i < result.length; i++) {
                    for (var key in result[i]) {
                        result[i][key] = decrypt(result[i][key]);
                    }
                }
                callback(null, result);
                database.end();
            }
        });
    }
};

const wrapper = require("./encryptionWrapper.js");