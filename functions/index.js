const { onCall, HttpsError } = require("firebase-functions/v2/https");
const functionsV1 = require("firebase-functions/v1");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");

admin.initializeApp();
const db = admin.firestore();

// ---- Limits (kobo — 1 naira = 100 kobo, keeps everything integer) ----
const SINGLE_TX_LIMIT = 500000;  // ₦5,000
const DAILY_LIMIT = 2000000;     // ₦20,000
const MAX_PIN_ATTEMPTS = 4;

// Excludes visually-ambiguous characters (0/O, 1/I/L)
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function generateWalletCode() {
  const part = () =>
    Array.from({ length: 3 }, () => CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]).join("");
  return `${part()}-${part()}`;
}

async function uniqueWalletCode() {
  for (let i = 0; i < 10; i++) {
    const code = generateWalletCode();
    const existing = await db.collection("wallets").where("walletCode", "==", code).limit(1).get();
    if (existing.empty) return code;
  }
  throw new Error("Could not generate a unique wallet code after 10 tries");
}

// ============================================================
// onUserCreate — fires on signup. Creates the public wallet doc
// AND the private security subdoc in one atomic batch. This is
// the ONLY place wallet docs are ever created.
// ============================================================
exports.onUserCreate = functionsV1.auth.user().onCreate(async (user) => {
  const walletCode = await uniqueWalletCode();
  const walletRef = db.collection("wallets").doc(user.uid);

  const batch = db.batch();
  batch.set(walletRef, {
    uid: user.uid,
    displayName: user.displayName || "",
    email: user.email || "",
    walletCode,
    balance: 0,
    mode: "pay",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  batch.set(walletRef.collection("private").doc("security"), {
    pinHash: null,
    pinSet: false,
    failedPinAttempts: 0,
    locked: false,
    dailySpent: 0,
    dailySpentDate: null,
  });
  await batch.commit();
});

// ============================================================
// getWalletStatus — callable. Dashboard calls this on load since
// it can't read the private/security doc directly. Also doubles
// as the "logging back in unlocks a locked wallet" mechanism —
// per the trust-band copy on the landing page.
// ============================================================
exports.getWalletStatus = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const securityRef = db.collection("wallets").doc(uid).collection("private").doc("security");
  const snap = await securityRef.get();
  const data = snap.exists ? snap.data() : {};
  const wasLocked = !!data.locked;

  if (wasLocked) {
    await securityRef.set({ locked: false, failedPinAttempts: 0 }, { merge: true });
  }

  return { pinSet: !!data.pinSet, wasLocked };
});

// ============================================================
// setPin — callable. Used for first-time PIN setup (?setup=pin)
// and for changing the PIN later from settings.
// ============================================================
exports.setPin = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const { pin } = request.data;
  if (typeof pin !== "string" || !/^\d{4,6}$/.test(pin)) {
    throw new HttpsError("invalid-argument", "PIN must be 4-6 digits.");
  }

  const pinHash = await bcrypt.hash(pin, 10);
  await db.collection("wallets").doc(uid).collection("private").doc("security").set(
    { pinHash, pinSet: true, failedPinAttempts: 0, locked: false },
    { merge: true }
  );
  return { success: true };
});

// ============================================================
// chargeWallet — callable, invoked by the VENDOR's device once
// the student has entered their PIN on that same screen. Does
// PIN verification, limit checks, and the fund transfer in one
// atomic Firestore transaction.
// ============================================================
exports.chargeWallet = onCall(async (request) => {
  const vendorUid = request.auth?.uid;
  if (!vendorUid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const { studentCode, amount, pin } = request.data;
  if (typeof studentCode !== "string" || !studentCode.trim()) {
    throw new HttpsError("invalid-argument", "Missing student code.");
  }
  const amt = Math.round(Number(amount));
  if (!Number.isFinite(amt) || amt <= 0) {
    throw new HttpsError("invalid-argument", "Invalid amount.");
  }
  if (amt > SINGLE_TX_LIMIT) {
    throw new HttpsError("failed-precondition", "This exceeds the ₦5,000 per-transaction limit.");
  }
  if (typeof pin !== "string" || !/^\d{4,6}$/.test(pin)) {
    throw new HttpsError("invalid-argument", "Invalid PIN.");
  }

  const walletsRef = db.collection("wallets");
  const studentQuery = await walletsRef
    .where("walletCode", "==", studentCode.trim().toUpperCase())
    .limit(1)
    .get();
  if (studentQuery.empty) {
    throw new HttpsError("not-found", "No wallet found for that code.");
  }
  const studentUid = studentQuery.docs[0].id;

  if (studentUid === vendorUid) {
    throw new HttpsError("failed-precondition", "You can't charge your own wallet.");
  }

  const studentWalletRef = walletsRef.doc(studentUid);
  const studentSecurityRef = studentWalletRef.collection("private").doc("security");
  const vendorWalletRef = walletsRef.doc(vendorUid);
  const txRef = db.collection("transactions").doc();

  return db.runTransaction(async (t) => {
    const [securitySnap, studentWalletSnap, vendorWalletSnap] = await Promise.all([
      t.get(studentSecurityRef),
      t.get(studentWalletRef),
      t.get(vendorWalletRef),
    ]);

    if (!securitySnap.exists || !studentWalletSnap.exists || !vendorWalletSnap.exists) {
      throw new HttpsError("not-found", "Wallet not fully set up.");
    }
    const security = securitySnap.data();
    const studentWallet = studentWalletSnap.data();
    const vendorWallet = vendorWalletSnap.data();

    if (!security.pinSet) {
      throw new HttpsError("failed-precondition", "This student hasn't set up a PIN yet.");
    }
    if (security.locked) {
      throw new HttpsError("permission-denied", "This wallet is locked. The student needs to log in to unlock it.");
    }

    const pinMatches = await bcrypt.compare(pin, security.pinHash);
    if (!pinMatches) {
      const attempts = (security.failedPinAttempts || 0) + 1;
      const update = { failedPinAttempts: attempts };
      if (attempts >= MAX_PIN_ATTEMPTS) update.locked = true;
      t.set(studentSecurityRef, update, { merge: true });
      throw new HttpsError(
        "permission-denied",
        attempts >= MAX_PIN_ATTEMPTS
          ? "Wrong PIN. This wallet is now locked."
          : `Wrong PIN. ${MAX_PIN_ATTEMPTS - attempts} attempt(s) left.`
      );
    }

    // Daily cap resets automatically on a new calendar day
    const todayStr = new Date().toISOString().slice(0, 10);
    const dailySpent = security.dailySpentDate === todayStr ? (security.dailySpent || 0) : 0;
    if (dailySpent + amt > DAILY_LIMIT) {
      throw new HttpsError("failed-precondition", "This would exceed the ₦20,000 daily limit.");
    }
    if ((studentWallet.balance || 0) < amt) {
      throw new HttpsError("failed-precondition", "Insufficient balance.");
    }

    t.update(studentWalletRef, { balance: admin.firestore.FieldValue.increment(-amt) });
    t.update(vendorWalletRef, { balance: admin.firestore.FieldValue.increment(amt) });
    t.set(
      studentSecurityRef,
      { failedPinAttempts: 0, dailySpent: dailySpent + amt, dailySpentDate: todayStr },
      { merge: true }
    );
    t.set(txRef, {
      payerUid: studentUid,
      payerName: studentWallet.displayName || "",
      vendorUid: vendorUid,
      vendorName: vendorWallet.displayName || "",
      amount: amt,
      status: "completed",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, txId: txRef.id };
  });
});