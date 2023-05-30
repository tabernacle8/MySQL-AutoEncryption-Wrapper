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
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return(encrypted.toString("hex"));
}


function decrypt(encryptedText) {
    if(encryptedText == null) return null;
    if(!encryptedText.toString().includes(config.settings.securedBuffer) && config.security.allowDecryptionBypass) return encryptedText;


    encryptedText = encryptedText.replace(config.settings.securedBuffer, "");
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
    let encryptedBuffer = Buffer.from(encryptedText, 'hex');
    let decrypted = decipher.update(encryptedBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}


exports.query = function (query, params, callback) {

    //Comment check
    if(!config.security.allowQueryComments && (query.includes("--") ||query.includes("/*") || query.includes("*/"))){
        callback("Query failed: config does not permit query comments", null);
        return;
    }

    //Duplicate params for unencrypted checks
    var unencryptedParams = null;
    if(config.security.allowUnencryptedRemnants){
        unencryptedParams = JSON.parse(JSON.stringify(params));;
    }
            

    //Encrypt each parameter and then pass it to the query
    for (var i = 0; i < params.length; i++) {

        if(params[i].toString().includes(config.settings.securedBuffer)){
            callback("Query failed: parameter is already encrypted", null);
            return;
        }

        try{
            var encryptedParam = config.settings.securedBuffer+(encrypt(params[i].toString()));

            if (encryptedParam.length > config.settings.maxTableLength) {
                callback("Query failed: parameter is too long", null);
                return;
            }

            params[i] = encryptedParam;
        }

        catch(err){
            callback("Query failed: parameter failed to encrypt", null);
            return;
        }
    }

    //Establish connection
    var database = mysql.createConnection({
        host: config.database.host,
        user: config.database.user,
        password: config.database.password,
        database: config.database.database,
    });

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

                        try{
                        result[i][key] = decrypt(result[i][key]);
                        }
                        catch(err){
                            callback("Query failed: parameter failed to decrypt", null);
                            database.end();
                            return;
                        }
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
                        
                        try{
                        result[i][key] = decrypt(result[i][key]);
                        }
                        catch(err){
                            callback("Query failed: parameter failed to decrypt", null);
                            database.end();
                            return;
                        }
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

                                    try{
                                    result[i][key] = decrypt(result[i][key]);
                                    }
                                    catch(err){
                                        callback("Query failed: parameter failed to decrypt", null);
                                        database.end();
                                        return;
                                    }
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