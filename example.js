const { wrap } = require("module");
wrapper = require("./encryptionWrapper.js");


wrapper.query("INSERT INTO users VALUES (?,?)", ["Hey this is a users name", 12345], function (err, result) {
});


wrapper.query("SELECT * FROM users", [], function (err, result) {
  if (err) {
    console.log(err);
    return;
  }

  //For each result log the name and id
    for (var i = 0; i < result.length; i++) {
        console.log(result[i].name + " | " + result[i].id);
    }
 
});