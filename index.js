
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

const app = express();
const PORT = process.env.PORT || 3000;

// Firebase Admin initialization
const serviceAccount = require("./firebase-service-account.json");

initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Basic server status
app.get("/", (req, res) => {
  res.json({
    status: "running",
    service: "MS Global E-Store ImageKit Backend",
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Verify Firebase Authentication ID token
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

// Only approved and active sellers may request upload credentials
app.get("/auth", verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.user.uid;

    // Seller document ID must match Firebase Authentication UID
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

    if (
      !privateKey ||
      !publicKey ||
      privateKey === "your_private_key_here" ||
      publicKey === "your_public_key_here"
    ) {
      return res.status(500).json({
        error: "ImageKit keys are not configured",
      });
    }

    // Generate temporary ImageKit upload authorization
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

// Local testing only. Hosting configuration will be handled later.
app.listen(PORT, "127.0.0.1", () => {
  console.log(
    `ImageKit backend running at http://127.0.0.1:${PORT}`
  );
});
