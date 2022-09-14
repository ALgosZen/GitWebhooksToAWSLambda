const { createHmac } = require('crypto');
const secretKey = 'classik09';
const expectedSign = 'sha256='+createHmac('sha256', secretKey)
.update('Man oh man do I love node!')
.digest('hex');
console.log(expectedSign);