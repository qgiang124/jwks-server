const express = require('express');
const jose = require('node-jose');
const jwt = require('jsonwebtoken');
const ms = require('ms');

const app = express();
const port = 8080;

const keyStore = jose.JWK.createKeyStore();

// Generate a unique Key ID (kid)
const generateKid = () => {
  return jose.util.randomBytes(8).toString('hex');
}

// Generate an unexpired JWT
const generateJWT = async () => {
  const [key] = await keyStore.all({ use: 'sig' });

  const opt = { compact: true, jwk: key, fields: { typ: 'jwt' } };
  const payload = {
    sub: 'test',
    iat: Math.floor(Date.now() / 1000),
  };
  return await jose.JWS.createSign(opt, key)
    .update(JSON.stringify(payload))
    .final();
}

// Generate RSA key pair
const generateKeys = async () => {
  const kid = generateKid();
  const result = await keyStore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' }, true, { kid });
  return result;
};

// Endpoint to generate RSA key pair
app.get('/keys', async (req, res) => {
  try {
    const keys = await generateKeys();
    res.json({ success: true, message: 'Keys generated', keys });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// Endpoint to retrieve keys in JWKS format
app.get('/jwks', async (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const keys = await keyStore.all({ use: 'sig' });

    const jwks = {
      keys: keys
        .filter(key => key.kid && key.kid.length > 0)
        .map(key => key.toJSON()),
    };

    res.json(jwks);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

 // Authentication endpoint
app.post('/auth', async (req, res) => {
    try {
      const expired = req.query.expired === 'true';
      const token = await generateJWT(expired);
      res.json({ success: true, token });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
  });
  

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
