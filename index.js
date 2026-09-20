const cbor = require("cbor");
const cose = require("cose-js");
const crypto = require("crypto");

// Create signing keys
const { privateKey, publicKey } =
  crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });

const privateJwk = privateKey.export({ format: "jwk" });
console.log("Private JWK:");
console.log(privateJwk);
//process.exit(0);
const publicJwk = publicKey.export({ format: "jwk" });
console.log("Public JWK:");
console.log(publicJwk);
//process.exit(0);
const toBuffer = (value) => Buffer.from(value, "base64url");

async function createCWT() {

  // User information
  const user = {
    userId: 12345,
    name: "John"
  };

  // CWT claims
  const claims = {
    2: user.userId,                         // sub
    4: Math.floor(Date.now() / 1000) + 300, // exp
    100: user.name                          // custom claim
  };

  // CBOR encode
  const payload = cbor.encode(claims);

  // COSE_Sign1
  const signed = await cose.sign.create(
    { p: { alg: "ES256" } },
    payload,
    { key: { d: toBuffer(privateJwk.d) } }
  );

  return Buffer.from(signed).toString("base64url");
}

async function verifyCWT(cwt) {

  const signed = Buffer.from(cwt, "base64url");

  const payload = await cose.sign.verify(signed, {
    key: {
      x: toBuffer(publicJwk.x),
      y: toBuffer(publicJwk.y)
    }
  });

  const claims = cbor.decodeFirstSync(payload);

  if (claims[4] < Math.floor(Date.now() / 1000)) {
    throw new Error("Expired");
  }

  console.log("userId:", claims[2]);
  console.log("name:", claims[100]);
}

// Create signed CWT
(async () => {

  const cwt = await createCWT();

  console.log("Signed CWT:");
  console.log(cwt);

  await verifyCWT(cwt);
})();