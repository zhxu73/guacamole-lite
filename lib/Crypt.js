const Crypto = require('crypto');

class Crypt {

    constructor(app) {
        this.server = app;
    }

    decrypt(encodedString) {
        let encoded = JSON.parse(this.constructor.base64decode(encodedString));

        encoded.iv = this.constructor.base64decode(encoded.iv);
        encoded.value = this.constructor.base64decode(encoded.value, 'binary');
        if (encoded.hmac && this.server.clientOptions.crypt.hmacKey) {
            const hmac = Crypto.createHmac('sha256', this.server.clientOptions.crypt.hmacKey).update(encoded.value).digest('hex');
            if (hmac !== encoded.hmac) {
                throw new Error('hmac mismatched for token cipher text');
            }
        }

        const decipher = Crypto.createDecipheriv(this.server.clientOptions.crypt.cypher, this.server.clientOptions.crypt.key, encoded.iv);

        let decrypted = decipher.update(encoded.value, 'binary', 'ascii');
        decrypted += decipher.final('ascii');

        return JSON.parse(decrypted);
    }

    static base64decode(string, mode) {
        return Buffer.from(string, 'base64').toString(mode || 'ascii');
    }

}

module.exports = Crypt;
