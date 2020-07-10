const NodeRSA = require('node-rsa');

module.exports = async function (context, req) {
    context.log('JavaScript HTTP trigger function processed a request.');

    var text;
    var result = '';

    let needEncryption = req.query.needEncryption;

    if (req.query.text) {
        text = req.query.text.replace('-', '+').replace('_', '/');
    } else {
        context.res = {
            status: 400,
            body: "Please specify text for encryption/decryption"
        };
        context.done();
    }

    try {
        if (needEncryption == "true") {
            context.log("Started text encryption");

            let privateKey = new NodeRSA(process.env['PrivateKeyString'], 'pkcs8');
            result = privateKey.encryptPrivate(text, 'base64');

            context.log("Finished text encryption");
        } else {
            context.log("Started text decryption");

            let publicKey = new NodeRSA(process.env['PublicKeyString'], "public");
            result = publicKey.decryptPublic(text, 'utf8');

            context.log("Finished text decryption");
        }

        context.res = {
            body: {text: result}
        };
    } catch (err) {
        context.res = {
            status: 400,
            body: err.message
        };

        context.log(err.message);

        context.done();
    }
}

