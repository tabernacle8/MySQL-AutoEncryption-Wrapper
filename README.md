# MySQL Database Auto-Encryption Wrapper

This project is a Node.js based MySQL database wrapper with built-in automatic AES-256-CBC encryption.
This wrapper allows you to write SQL queries as normal, but parameters are automatically encrypted and decrypted for you.

It's mainly designed to teach myself about database wrappers and encryption. But it should work just fine for your newer projects too.

## Features

- Automatic encryption and decryption of parameters sent and received from the database.
- Error handling for already encrypted parameters or oversized parameters.

## Installation

Before using this wrapper, make sure that you have both Node.js and npm installed on your machine.

To install, first clone this repository,

Then install the necessary Node.js dependencies:

```javascript
npm install mysql crypto
```

Finally, edit the config.json file to match your database credentials and encryption key information.
(If you need a new low-security key, try using the keygen.js (insecure) file to generate one)

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

## Restrictions

Please note that comparison statements in your SQL queries will not function as expected if you use the automatic encryption provided by this wrapper. The reason being, the wrapper encrypts parameters which would disrupt the normal comparison operation in SQL.

In addition, this wrapper may not work correctly if the columns in your database table are not designed to hold strings or have a character length limit that is too small for the encrypted data. Ensure your tables can accommodate nvarchar or similar data types and have sufficient length.

THIS IS NOT A HIGH SECURITY WRAPPER, IT IS SIMPLY A "DRAG AND DROP" LAZY SOLUTION, DO NOT USE THIS IN HIGH SECURITY APPLICATIONS.
I wrote this for fun and to learn a little about how a database wrapper works.
(But frankly, you already knew this, just wanted to make it extra clear)

## Contributing

Contributions are always welcome. Let's learn about wrappers together!
Just submit a pull request and I'll take a look.

## License

This project is licensed under the terms of the MIT License.

## Support

If you're having issues, please submit an issue on GitHub
