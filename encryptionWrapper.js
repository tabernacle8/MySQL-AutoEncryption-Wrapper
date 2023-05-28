const mysql = require("mysql");
const crypto = require("crypto");
const config = require('./wrapperConfig.json');


const algorithm = "aes-256-cbc";
const key = Buffer.from(
    config.encryption.key,
    "hex"
);
const iv = Buffer.from(config.encryption.iv, "hex");


function encrypt(text) {
    try{
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return {
        iv: iv.toString("hex"),
        encryptedData: encrypted.toString("hex")
    };
    
    }
    catch(err){
        throw err;
    }
}


function decrypt(encryptedText) {
    if(encryptedText == null) return null;
    if(!encryptedText.toString().includes(config.settings.securedBuffer) && config.security.allowDecryptionBypass) return encryptedText;

    try{
    encryptedText = encryptedText.replace(config.settings.securedBuffer, "");
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
    let encryptedBuffer = Buffer.from(encryptedText, 'hex');
    let decrypted = decipher.update(encryptedBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
    }

    catch(err){
        throw err;
    }
    
}


exports.query = function (query, params, callback) {

    //Establish connection
    var database = mysql.createConnection({
        host: config.database.host,
        user: config.database.user,
        password: config.database.password,
        database: config.database.database,
    });

    //Duplicate params for unencrypted checks
    var unencryptedParams = null;
    if(config.security.allowUnencryptedRemnants){
        unencryptedParams = JSON.parse(JSON.stringify(params));;
    }
            

    //Encrypt each parameter and then pass it to the query
    for (var i = 0; i < params.length; i++) {
        if(params[i].toString().includes(config.settings.securedBuffer)){
            callback("Query failed: parameter " + i + " is already encrypted", null);
            database.end();
            return;
        }
        params[i] = config.settings.securedBuffer+(encrypt(params[i].toString()).encryptedData);
    }

    //If any params are over X characters, log and stop the query
    for (var i = 0; i < params.length; i++) {
        if (params[i].length > config.settings.maxTableLength) {
            callback("Query failed: parameter " + i + " is too long", null);
            database.end();
            return;
        }
    }

    //Execute the query with length 0
    if (params.length == 0 && config.security.allowEmptyParams) {
        database.query(query, [], function (err, result) {
            if (err) {
                callback(err, null);
            } else {
                if (result.length == 0) {
                    callback(null, null);
                    database.end();
                    return;
                }

                //Decrypt and publish results
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
    
    //Execute the query with length 1 or more
    else if(params.length>=1){
        database.query(query, params, function (err, result) {
            if (err) {
                callback(err, null);
                database.end();
            } else {

                //Decrypt and publish results
                for (var i = 0; i < result.length; i++) {
                    for (var key in result[i]) {
                        result[i][key] = decrypt(result[i][key]);
                    }
                }

                //If result is null, and unencryptedParams is true, try running query again but with unencrypted params
                if ((result.length == 0 || result.affectedRows === 0) && config.security.allowUnencryptedRemnants) {
                    database.query(query, unencryptedParams, function (err, result) {
                        if (err) {
                            callback(err, null);
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
                else{
                callback(null, result);
                database.end();
                }
            }
        });

    }
};

const wrapper = require("./encryptionWrapper.js");