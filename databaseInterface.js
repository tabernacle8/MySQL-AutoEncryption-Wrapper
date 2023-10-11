const readline = require('readline');
const database = require('./encryptionWrapper.js');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});


function promptQuery() {
    rl.question('Enter your SQL query (Example: SELECT * FROM test WHERE id=?): ', (query) => {
        if (!query) {
            console.log('Exiting.');
            rl.close();
            return;
        }
        promptArguments(query);
    });
}

function promptArguments(query) {
    rl.question('Enter the arguments as comma-separated values (e.g. arg1,arg2,arg3): ', (argsInput) => {
        const args = argsInput.split(',').map(arg => arg.trim());

        executeQuery(query, args);
    });
}


function executeQuery(query, args) {
    database.query(query, args, (err, result) => {
        if (err) {
            console.error('Error:', err.message);
        } else {
            console.log('Result:', result);
        }

        // Ask the user for another query or close the application.
        promptQuery();
    });
}


console.log('Database Debugging Tool');
promptQuery();