
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

const app = express();
const PORT = process.env.PORT || 3000;

// Secure Firebase credentials from hosting environment
let serviceAccount;

try {
  const rawCredentials = process.env.FIREBASE_SERVICE_ACCOUNT;

  if (!rawCredentials) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT is missing");
  }

  serviceAccount = JSON.parse(rawCredentials);

  if (
    !serviceAccount.project_id ||
    !serviceAccount.client_email ||
    !serviceAccount.private_key
  ) {
    throw new Error("Firebase service account credentials are incomplete");
  }

  serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");

  if (getApps().length === 0) {
    initializeApp({
      credential: cert(serviceAccount),
    });
  }
} catch (error) {
  console.error("Firebase initialization failed:", error.message);
  process.exit(1);
}

const db = getFirestore();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/", (req, res) => {
  res.json({
    status: "running",
    service: "MS Global E-Store ImageKit Backend",
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Firebase login token required",
    });
  }

  try {
    const idToken = authHeader.substring(7);
    req.user = await getAuth().verifyIdToken(idToken);
    return next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired Firebase login token",
    });
  }
}

app.get("/auth", verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.user.uid;

    const sellerDoc = await db
      .collection("sellerProfiles")
      .doc(uid)
      .get();

    if (!sellerDoc.exists) {
      return res.status(403).json({
        error: "Seller profile not found",
      });
    }

    const seller = sellerDoc.data();

    if (
      seller.uid !== uid ||
      seller.role !== "seller" ||
      seller.active !== true ||
      seller.status !== "Approved & Active"
    ) {
      return res.status(403).json({
        error: "Seller is not approved and active",
      });
    }

    const privateKey = process.env.IMAGEKIT_PRIVATE_KEY;
    const publicKey = process.env.IMAGEKIT_PUBLIC_KEY;

    if (!privateKey || !publicKey) {
      return res.status(500).json({
        error: "ImageKit keys are not configured",
      });
    }

    const token = crypto.randomUUID();
    const expire = Math.floor(Date.now() / 1000) + 30 * 60;

    const signature = crypto
      .createHmac("sha1", privateKey)
      .update(token + expire)
      .digest("hex");

    return res.json({
      token,
      expire,
      signature,
      publicKey,
    });
  } catch (error) {
    console.error("Upload authorization failed:", error.message);

    return res.status(500).json({
      error: "Could not authorize upload",
    });
  }
});

// Listen on the hosting platform's assigned port
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MS Global ImageKit backend listening on port ${PORT}`);
});
