import crypto from 'crypto';

const clientOptions ={
  cypher: 'AES-256-CBC',
  key: 'MySuperSecretKeyForParamsToken12',
  hmacKey: 'MySuperSecretKeyForHMAC',
};

const encrypt = (value) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(clientOptions.cypher, clientOptions.key, iv);

  let crypted = cipher.update(JSON.stringify(value), 'utf8', 'base64');
  crypted += cipher.final('base64');

  const data = {
    iv: iv.toString('base64'),
    value: crypted,
  };

  let jsonstr = JSON.stringify(data);
  let encoded = new Buffer(jsonstr).toString('base64');
  return encoded;
};

const encryptAndHMAC = (value) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(clientOptions.cypher, clientOptions.key, iv);

  let crypted = cipher.update(JSON.stringify(value), 'utf8', 'base64');
  crypted += cipher.final('base64');
  const hmac = Crypto.createHmac("sha256", clientOptions.hmacKey).update(crypted).digest('hex');

  const data = {
    iv: iv.toString('base64'),
    value: crypted,
    hmac: hmac, 
  };

  let jsonstr = JSON.stringify(data);
  let encoded = new Buffer(jsonstr).toString('base64');
  return encoded;
};

export default encrypt;
