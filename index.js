const express = require("express");
const cbor = require("cbor");
const cose = require("cose-js");
const crypto = require("crypto");
const path = require("path");

const app = express();
const port = 3000;
const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

const users = [
  {
    userId: 12345,
    username: "john",
    password: "secret123",
    name: "John Doe",
    email: "john@example.com",
    role: "admin",
    department: "Engineering",
    profile: {
      city: "Tokyo",
      timezone: "Asia/Tokyo",
      bio: "Platform engineer"
    }
  },
  {
    userId: 67890,
    username: "alice",
    password: "welcome456",
    name: "Alice Smith",
    email: "alice@example.com",
    role: "user",
    department: "Sales",
    profile: {
      city: "Osaka",
      timezone: "Asia/Tokyo",
      bio: "Account manager"
    }
  }
];

const findUserByUsername = (username) => users.find((user) => user.username === username);
const findUserById = (userId) => users.find((user) => user.userId === Number(userId));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "P-256"
});

const privateJwk = privateKey.export({ format: "jwk" });

const publicJwk = publicKey.export({ format: "jwk" });

const toBuffer = (value) => Buffer.from(value, "base64url");

async function authMiddleware(req, res, next) {
  console.log("authMiddleware called");
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const signed = Buffer.from(token, "base64url");
    const payload = await cose.sign.verify(signed, {
      key: {
        x: toBuffer(publicJwk.x),
        y: toBuffer(publicJwk.y)
      }
    });

    const claims = cbor.decodeFirstSync(payload);

    if (claims[1] !== ISSUER) {
      throw new Error("Invalid issuer");
    }

    if (claims[3] !== AUDIENCE) {
      throw new Error("Invalid audience");
    }

    if (claims[4] !== undefined && claims[4] < Math.floor(Date.now() / 1000)) {
      throw new Error("Expired");
    }

    const userId = Number(claims[2]);
    const user = findUserById(userId);

    if (!user) {
      throw new Error("User not found");
    }

    req.user = {
      userId: user.userId,
      username: user.username,
      role: user.role
    };

    req.auth = {
      tokenClaims: claims
    };

    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function createCWT(user) {
  const claims = {
    1: ISSUER,
    2: user.userId,
    3: AUDIENCE,
    4: Math.floor(Date.now() / 1000) + 300,
    100: user.name,
    101: user.email,
    102: user.role
  };

  const payload = cbor.encode(claims);

  return cose.sign.create(
    { p: { alg: "ES256" } },
    payload,
    { key: { d: toBuffer(privateJwk.d) } }
  ).then((signed) => Buffer.from(signed).toString("base64url"));
}

async function verifyCWT(cwt, expectedUserId) {
  const signed = Buffer.from(cwt, "base64url");

  const payload = await cose.sign.verify(signed, {
    key: {
      x: toBuffer(publicJwk.x),
      y: toBuffer(publicJwk.y)
    }
  });

  const claims = cbor.decodeFirstSync(payload);

  if (claims[1] !== ISSUER) {
    throw new Error("Invalid issuer");
  }

  if (claims[2] !== expectedUserId) {
    throw new Error("Invalid subject");
  }

  if (claims[3] !== AUDIENCE) {
    throw new Error("Invalid audience");
  }

  if (claims[4] !== undefined && claims[4] < Math.floor(Date.now() / 1000)) {
    throw new Error("Expired");
  }

  return claims;
}

app.get("/login-form", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login-form.html"));
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt: username=${username}, password=${password}`);
  const user = findUserByUsername(username);
  console.log(user)
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = await createCWT(user);
  return res.json({
    token,
    user: {
      userId: user.userId,
      username: user.username,
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
});

app.get("/user-profile", authMiddleware, (req, res) => {
  const user = findUserById(req.user.userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  return res.json({
    user: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role
    },
    auth: {
      issuer: req.auth.tokenClaims[1],
      subject: req.auth.tokenClaims[2],
      audience: req.auth.tokenClaims[3],
      expiresAt: req.auth.tokenClaims[4]
    },
    profile: {
      name: user.name,
      email: user.email,
      department: user.department,
      profile: user.profile
    }
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`Open http://localhost:${port}/login-form`);
  console.log("Demo credentials: john / secret123");
});