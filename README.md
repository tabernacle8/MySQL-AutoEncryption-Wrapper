# MySQL Database Auto-Encryption Wrapper

This project is a Node.js based MySQL database wrapper with built-in automatic AES-256-CBC encryption and encryption migration.
This wrapper allows you to write SQL queries as normal, but parameters are automatically encrypted and decrypted for you.
It can also work interchangeably with an old database that has both encrypted and unencrypted data.

It's mainly designed to teach myself about database wrappers and encryption. Never should you ever use this for anything remotely secure or public. Please.

## Features

- Automatic encryption and decryption of parameters sent and received from the database.
- Error handling for already encrypted parameters or oversized parameters.
- Automatically handles databases with both unencrypted data and encrypted data (See `wrapperConfig.json`)

## Installation

Before using this wrapper, make sure that you have both Node.js and npm installed on your machine.

To install, first clone this repository,

Then install the necessary Node.js dependencies:

```javascript
npm install mysql crypto
```

Finally, edit the `wrapperConfig.json` file to match your database credentials and encryption key information.
(If you need a new low-security key, try using the keygen.js (insecure) file to generate one)

If you are using this on a completely new database, set all security group config settings to false and `securedBuffer` to empty.

## Usage

To use the database wrapper, simply require the `encryptionWrapper.js` file in your Node.js code and call the `query()` function:

```javascript
const db = require('./encryptionWrapper.js');

db.query('SELECT * FROM users WHERE username = ?', ['username'], function(err, result) {
    if (err) {
        console.log(err);
    } else {
        console.log(result);
    }
});
```

This function takes in a SQL query string, an array of parameters, and a callback function.
See `example.js` for more help 

## Config Explanations

- `allowUnencryptedRemnants` - Allow re-queries with unencrypted data if the original query returns null. (Leave true for compatibility with partially un-encrypted databases. This setting does lead to 2x memory usage)

- `allowDecryptionBypass` - Skip decrypting data if it does not appear to be encrypted. (Leave true for compatibility with partially un-encrypted databases)

- `allowEmptyParams` - Allow queries without parameters to be sent to the database

- `securedBuffer` - Proceeded all text with this string before insertion to signal that it is encrypted. (Setting this to empty will prevent compatibility with partially un-encrypted databases)

- `allowQueryComments` - Allow queries to contain comments

- `returnVagueErrors` - Return vague errors instead of detailed errors

- `reduceTextSize` - Use base64 encoding


## Restrictions

This wrapper may not work correctly if the columns in your database table are not designed to hold strings or have a character length limit that is too small for the encrypted data (Change max size in the `wrapperConfig.json`). Ensure your tables can accommodate nvarchar or similar data types and have sufficient length.

This project assumes the iv value never changes, which is not how this encryption format is supposed to work. I'm probably going to change it later.

I wrote this for fun and to learn a little about how a database wrapper works.
(But frankly, you already knew this, just wanted to make it extra clear)

## Contributing

Contributions are always welcome. Let's learn about wrappers together!
Just submit a pull request and I'll take a look.

## License

This project is licensed under the terms of the MIT License.

## Support

If you're having issues, please submit an issue on GitHub
