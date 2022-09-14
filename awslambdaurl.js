require('dotenv').config()
//create AWS lambda function URL and copy paste
//the following node js function
//deploy and get the url to paste in git->settings-> webhook
const { createHmac } = require('crypto');
console.log(process.env.SECRET_KEY)
const secretKey = process.env.SECRET_KEY;

exports.handler = async (event) => {
   // const expectedSign = 'sha256=${createHmac(“sha256”, secretKey).update(event.body).digest(“hex”)}';
    const expectedSign = 'sha256='+createHmac('sha256', secretKey).update(event.body).digest('hex');

    const currentSign = event.headers['X-Hub-Signature-256'];
    if (expectedSign !== currentSign){
        return {statusCode: 400}
    }
    
    console.log(event);
    console.log('expected: ', expectedSign);
    console.log('received: ',currentSign);
    console.log(event.headers['X-GitHub-Event']);
    console.log(JSON.parse(event.body));
    return {statusCode: 200};
};