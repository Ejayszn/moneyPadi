const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const functionsV1 = require("firebase-functions/v1");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const crypto = require("crypto");
const { onSchedule } = require("firebase-functions/v2/scheduler");

admin.initializeApp();
const db = admin.firestore();

const PAYSTACK_SECRET = defineSecret("PAYSTACK_SECRET");
const PAYSTACK_BASE = "https://api.paystack.co";
const TELEGRAM_BOT_TOKEN = defineSecret("TELEGRAM_BOT_TOKEN");
const TELEGRAM_WEBHOOK_SECRET = defineSecret("TELEGRAM_WEBHOOK_SECRET");
const TELEGRAM_API_BASE = "https://api.telegram.org/bot";

// ---- Topup ----
const TOPUP_MARGIN = 1000; // ₦10 in kobo — flat MoneyPadi margin on every topup

// ---- Withdrawal ----
const MIN_WITHDRAWAL = 50000; // ₦500 in kobo
function withdrawalFee(amountKobo) {
  // Mirrors Paystack's own transfer tiers — see docs/support articles
  if (amountKobo <= 500000) return 1000;      // ₦5,000 → ₦10
  if (amountKobo <= 5000000) return 2500;     // ₦50,000 → ₦25
  return 5000;                                 // above → ₦50
}
function stampDuty(amountKobo) {
  return amountKobo >= 1000000 ? 5000 : 0; // ₦10,000+ → ₦50 (NTA 2025)
}

// ---- Limits (kobo — 1 naira = 100 kobo, keeps everything integer) ----
const SINGLE_TX_LIMIT = 500000;  // ₦5,000
const DAILY_LIMIT = 2000000;     // ₦20,000
const MAX_PIN_ATTEMPTS = 4;

// Letters only, no digits. Excludes I and O — too easily
// confused with each other (and with 1/0) when read off a screen.
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ";

function generateWalletCode() {
  return Array.from({ length: 4 }, () => CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)]).join("");
}

async function uniqueWalletCode() {
  for (let i = 0; i < 10; i++) {
    const code = generateWalletCode();
    const existing = await db.collection("wallets").where("walletCode", "==", code).limit(1).get();
    if (existing.empty) return code;
  }
  throw new Error("Could not generate a unique wallet code after 10 tries");
}

function generateTelegramLinkToken() {
  return crypto.randomBytes(16).toString("hex");
}

async function sendTelegramMessage(chatId, text) {
  await axios.post(
    `${TELEGRAM_API_BASE}${TELEGRAM_BOT_TOKEN.value()}/sendMessage`,
    { chat_id: chatId, text, parse_mode: "HTML" },
    { timeout: 10000 }
  );
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
// setPin — callable. FIRST-TIME setup only (?setup=pin). Once a
// PIN exists, this refuses — changing it has to go through
// changePin (know your PIN) or resetPinAfterReauth (forgot your
// PIN) instead, never through here. Otherwise anyone holding an
// unlocked phone could silently overwrite the PIN.
// ============================================================
exports.setPin = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const { pin } = request.data;
  if (typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
    throw new HttpsError("invalid-argument", "PIN must be exactly 4 digits.");
  }

  const securityRef = db.collection("wallets").doc(uid).collection("private").doc("security");
  const securitySnap = await securityRef.get();
  if (securitySnap.exists && securitySnap.data().pinSet) {
    throw new HttpsError(
      "failed-precondition",
      "A PIN is already set. Use the change-PIN flow instead."
    );
  }

  const pinHash = await bcrypt.hash(pin, 10);
  await securityRef.set(
    { pinHash, pinSet: true, failedPinAttempts: 0, locked: false },
    { merge: true }
  );
  return { success: true };
});

// ============================================================
// changePin — callable. Used from Settings when the student
// DOES know their current PIN. Requires it, so someone who's
// just picked up an unlocked phone can't silently take over the
// wallet. Reuses the same failed-attempt lockout as chargeWallet
// — same threat model, same defense.
// ============================================================
exports.changePin = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const { currentPin, newPin } = request.data;
  if (typeof currentPin !== "string" || !/^\d{4}$/.test(currentPin)) {
    throw new HttpsError("invalid-argument", "Invalid current PIN.");
  }
  if (typeof newPin !== "string" || !/^\d{4}$/.test(newPin)) {
    throw new HttpsError("invalid-argument", "New PIN must be exactly 4 digits.");
  }

  const securityRef = db.collection("wallets").doc(uid).collection("private").doc("security");
  const securitySnap = await securityRef.get();
  if (!securitySnap.exists || !securitySnap.data().pinSet) {
    throw new HttpsError("failed-precondition", "No PIN set yet.");
  }
  const security = securitySnap.data();
  if (security.locked) {
    throw new HttpsError("permission-denied", "This wallet is locked. Log out and back in to unlock it.");
  }

  const matches = await bcrypt.compare(currentPin, security.pinHash);
  if (!matches) {
    const attempts = (security.failedPinAttempts || 0) + 1;
    const update = { failedPinAttempts: attempts };
    if (attempts >= MAX_PIN_ATTEMPTS) update.locked = true;
    await securityRef.set(update, { merge: true });
    throw new HttpsError(
      "permission-denied",
      attempts >= MAX_PIN_ATTEMPTS
        ? "Wrong PIN. This wallet is now locked."
        : `Wrong current PIN. ${MAX_PIN_ATTEMPTS - attempts} attempt(s) left.`
    );
  }

  const newHash = await bcrypt.hash(newPin, 10);
  await securityRef.set(
    { pinHash: newHash, failedPinAttempts: 0, locked: false },
    { merge: true }
  );
  return { success: true };
});

// ============================================================
// resetPinAfterReauth — callable. Used from "Forgot PIN?" when
// the student does NOT know their current PIN. Instead of the
// PIN, this trusts that the client just re-authenticated with
// their ACCOUNT PASSWORD via Firebase Auth's
// reauthenticateWithCredential, which refreshes auth_time on the
// ID token. We check auth_time is recent (last 5 min) rather
// than trusting anything the client sends us directly — that
// claim is set by Firebase itself and can't be forged.
// ============================================================
exports.resetPinAfterReauth = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const authTime = request.auth?.token?.auth_time;
  const nowSeconds = Date.now() / 1000;
  const REAUTH_WINDOW_SECONDS = 5 * 60;
  if (!authTime || nowSeconds - authTime > REAUTH_WINDOW_SECONDS) {
    throw new HttpsError(
      "failed-precondition",
      "Please re-enter your account password to continue."
    );
  }

  const { newPin } = request.data;
  if (typeof newPin !== "string" || !/^\d{4}$/.test(newPin)) {
    throw new HttpsError("invalid-argument", "New PIN must be exactly 4 digits.");
  }

  const newHash = await bcrypt.hash(newPin, 10);
  await db.collection("wallets").doc(uid).collection("private").doc("security").set(
    { pinHash: newHash, pinSet: true, failedPinAttempts: 0, locked: false },
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
  // in chargeWallet
  if (typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
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

// ============================================================
// TOPUP FLOW — Pay with Transfer only. Flat ₦10 (1000 kobo)
// MoneyPadi margin on every topup, regardless of size.
// ============================================================

exports.initiateTopup = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const amountKobo = Math.round(Number(request.data?.amount));
  if (!Number.isFinite(amountKobo) || amountKobo <= 0) {
    throw new HttpsError("invalid-argument", "Invalid amount.");
  }

  const userRecord = await admin.auth().getUser(uid);
  const totalChargeKobo = amountKobo + TOPUP_MARGIN;
  const topupRef = db.collection("topups").doc(); // reference = Firestore doc id
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min window

  try {
    const chargeRes = await axios.post(
      `${PAYSTACK_BASE}/charge`,
      {
        email: userRecord.email,
        amount: totalChargeKobo,
        currency: "NGN",
        reference: topupRef.id,
        bank_transfer: { account_expires_at: expiresAt },
      },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` }, timeout: 15000 }
    );

    // NOTE: verify this shape against a real sandbox response — Paystack's
    // bank_transfer charge payload has shifted field names across API
    // versions before. Check functions logs on first real test.
    const details = chargeRes.data?.data;

    await topupRef.set({
      uid,
      amountKobo,          // what the wallet gets credited
      totalChargeKobo,     // what the student actually transfers
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      reference: topupRef.id,
      totalChargeKobo,
      bankDetails: details, // account_number, bank_name, account_expires_at, etc.
    };
  } catch (err) {
    console.error("initiateTopup error:", err.response?.data || err.message);
    throw new HttpsError("internal", "Couldn't start the transfer. Try again.");
  }
});

// Shared idempotent credit logic — called by both verifyTopup (client
// poll) and topupWebhook (server push), whichever arrives first wins;
// the other becomes a no-op.
async function creditTopupIfPending(reference) {
  const topupRef = db.collection("topups").doc(reference);

  return db.runTransaction(async (t) => {
    const snap = await t.get(topupRef);
    if (!snap.exists) return { alreadyProcessed: false, notFound: true };
    const topup = snap.data();
    if (topup.status !== "pending") return { alreadyProcessed: true };

    const walletRef = db.collection("wallets").doc(topup.uid);
    t.update(walletRef, { balance: admin.firestore.FieldValue.increment(topup.amountKobo) });
    t.set(topupRef, { status: "completed", completedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    t.set(db.collection("transactions").doc(), {
      type: "topup",
      uid: topup.uid,
      amount: topup.amountKobo,
      fee: TOPUP_MARGIN,
      status: "completed",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { alreadyProcessed: false };
  });
}

exports.verifyTopup = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const reference = request.data?.reference;
  if (!reference) throw new HttpsError("invalid-argument", "Missing reference.");

  const topupSnap = await db.collection("topups").doc(reference).get();
  if (!topupSnap.exists || topupSnap.data().uid !== uid) {
    throw new HttpsError("not-found", "Topup not found.");
  }

  try {
    const verifyRes = await axios.get(`${PAYSTACK_BASE}/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` },
      timeout: 15000,
    });
    const tx = verifyRes.data?.data;

    if (tx.status !== "success") {
      return { credited: false, status: tx.status }; // still pending on Paystack's side
    }
    if (tx.amount !== topupSnap.data().totalChargeKobo || tx.currency !== "NGN") {
      throw new HttpsError("failed-precondition", "Payment details don't match.");
    }

    const result = await creditTopupIfPending(reference);
    return { credited: !result.alreadyProcessed, status: "success" };
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("verifyTopup error:", err.response?.data || err.message);
    throw new HttpsError("internal", "Couldn't verify payment.");
  }
});

// Single webhook endpoint — Paystack only allows one URL per account,
// so this dispatches on event type instead of using separate functions.
exports.paystackWebhook = onRequest({ secrets: [PAYSTACK_SECRET] }, async (req, res) => {
  const hash = crypto
    .createHmac("sha512", PAYSTACK_SECRET.value())
    .update(JSON.stringify(req.body))
    .digest("hex");
  if (hash !== req.headers["x-paystack-signature"]) {
    return res.status(401).send("Invalid signature");
  }

  const event = req.body;
  try {
    if (event.event === "charge.success") {
      await creditTopupIfPending(event.data.reference);
    } else if (event.event === "transfer.success") {
      await db.collection("transactions").doc(event.data.reference).set(
        { status: "completed" }, { merge: true }
      );
    } else if (event.event === "transfer.failed" || event.event === "transfer.reversed") {
      const txRef = db.collection("transactions").doc(event.data.reference);
      await db.runTransaction(async (t) => {
        const txSnap = await t.get(txRef);
        if (!txSnap.exists || txSnap.data().status !== "pending") return;
        const tx = txSnap.data();
        t.update(db.collection("wallets").doc(tx.uid), {
          balance: admin.firestore.FieldValue.increment(tx.amount),
        });
        t.set(txRef, { status: "failed" }, { merge: true });
      });
    }
    return res.status(200).send("OK");
  } catch (err) {
    console.error("paystackWebhook error:", err);
    return res.status(200).send("OK"); // 200 always — avoid Paystack retry storms
  }
});

// ============================================================
// WITHDRAWAL FLOW
// ============================================================

exports.listBanks = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  if (!request.auth?.uid) throw new HttpsError("unauthenticated", "You need to be logged in.");
  try {
    const res = await axios.get(`${PAYSTACK_BASE}/bank?currency=NGN`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` },
      timeout: 15000,
    });
    return { banks: res.data.data.map((b) => ({ name: b.name, code: b.code })) };
  } catch (err) {
    console.error("listBanks error:", err.response?.data || err.message);
    throw new HttpsError("internal", "Couldn't load bank list.");
  }
});

exports.resolveBankAccount = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  if (!request.auth?.uid) throw new HttpsError("unauthenticated", "You need to be logged in.");
  const { bankCode, accountNumber } = request.data || {};
  if (!bankCode || !/^\d{10}$/.test(accountNumber || "")) {
    throw new HttpsError("invalid-argument", "Enter a valid 10-digit account number.");
  }
  try {
    const res = await axios.get(`${PAYSTACK_BASE}/bank/resolve`, {
      params: { account_number: accountNumber, bank_code: bankCode },
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` },
      timeout: 15000,
    });
    return { accountName: res.data.data.account_name };
  } catch (err) {
    const paystackMessage = err.response?.data?.message;
    console.error("resolveBankAccount error:", err.response?.data || err.message);
    throw new HttpsError("not-found", paystackMessage || "Couldn't verify that account. Check the details and try again.");
  }
});

exports.saveBankAccount = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const { bankCode, bankName, accountNumber, accountName } = request.data || {};
  if (!bankCode || !bankName || !/^\d{10}$/.test(accountNumber || "") || !accountName) {
    throw new HttpsError("invalid-argument", "Missing or invalid bank details.");
  }

  try {
    const res = await axios.post(
      `${PAYSTACK_BASE}/transferrecipient`,
      { type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` }, timeout: 15000 }
    );
    const recipientCode = res.data.data.recipient_code;
    const last4 = accountNumber.slice(-4);

    await db.collection("wallets").doc(uid).collection("private").doc("bank").set({
      recipientCode, bankName, accountName, last4,
    });
    await db.collection("wallets").doc(uid).set(
      { bankOnFile: { bankName, accountName, last4 } },
      { merge: true }
    );

    return { success: true, bankName, accountName, last4 };
  } catch (err) {
    console.error("saveBankAccount error:", err.response?.data || err.message);
    throw new HttpsError("internal", "Couldn't save that bank account.");
  }
});

exports.requestWithdrawal = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const amountKobo = Math.round(Number(request.data?.amount));
  if (!Number.isFinite(amountKobo) || amountKobo < MIN_WITHDRAWAL) {
    throw new HttpsError("invalid-argument", "Minimum withdrawal is ₦500.");
  }

  const walletRef = db.collection("wallets").doc(uid);
  const bankRef = walletRef.collection("private").doc("bank");
  const [walletSnap, bankSnap] = await Promise.all([walletRef.get(), bankRef.get()]);

  if (!bankSnap.exists) throw new HttpsError("failed-precondition", "Link a bank account first.");
  if ((walletSnap.data()?.balance || 0) < amountKobo) {
    throw new HttpsError("failed-precondition", "Insufficient balance.");
  }

  const fee = withdrawalFee(amountKobo) + stampDuty(amountKobo);
  const netPayout = amountKobo - fee;
  if (netPayout <= 0) throw new HttpsError("failed-precondition", "Amount too small after fees.");

  const txRef = db.collection("transactions").doc();

  await walletRef.update({ balance: admin.firestore.FieldValue.increment(-amountKobo) });
  await txRef.set({
    type: "withdrawal",
    uid,
    amount: amountKobo,
    fee,
    netPayout,
    status: "pending",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  try {
    await axios.post(
      `${PAYSTACK_BASE}/transfer`,
      {
        source: "balance",
        amount: netPayout,
        recipient: bankSnap.data().recipientCode,
        reference: txRef.id,
        reason: "MoneyPadi withdrawal",
      },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` }, timeout: 15000 }
    );
    // NOTE: if OTP finalization is enabled on your Paystack transfers
    // settings, this call alone won't complete the payout — check your
    // dashboard's Transfer settings and disable OTP for this to be
    // fully automatic, or add a finalize-transfer step.
    return { success: true, txId: txRef.id, netPayout, fee };
  } catch (err) {
    console.error("requestWithdrawal transfer error:", err.response?.data || err.message);
    await walletRef.update({ balance: admin.firestore.FieldValue.increment(amountKobo) });
    await txRef.set({ status: "failed" }, { merge: true });
    throw new HttpsError("internal", "Withdrawal failed. Your balance has been refunded.");
  }
});

// ============================================================
// TELEGRAM — required onboarding step + daily code reminder
// ============================================================

// createTelegramLinkToken — callable. Dashboard calls this to get a
// one-time token, embeds it in a t.me/<bot>?start=<token> deep link.
// Telegram hands that token back to us on /start via the webhook.
exports.createTelegramLinkToken = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const token = generateTelegramLinkToken();
  await db.collection("telegramLinkTokens").doc(token).set({
    uid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { token };
});

// telegramWebhook — receives every message sent to the bot. We only
// act on /start <token> (completes linking) and /stop (unlinks).
// Verified via the secret_token Telegram echoes back on every call,
// which we set ourselves when registering the webhook (see setup notes).
exports.telegramWebhook = onRequest(
  { secrets: [TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET] },
  async (req, res) => {
    if (req.headers["x-telegram-bot-api-secret-token"] !== TELEGRAM_WEBHOOK_SECRET.value()) {
      return res.status(401).send("Unauthorized");
    }

    const message = req.body?.message;
    const chatId = message?.chat?.id;
    const text = (message?.text || "").trim();

    try {
      if (chatId && text.startsWith("/start")) {
        const token = text.split(" ")[1];
        if (!token) {
          await sendTelegramMessage(chatId, "Welcome to MoneyPadi. Open the app and tap \"Connect Telegram\" to link your account.");
          return res.status(200).send("OK");
        }

        const tokenRef = db.collection("telegramLinkTokens").doc(token);
        const tokenSnap = await tokenRef.get();
        if (!tokenSnap.exists) {
          await sendTelegramMessage(chatId, "That link has expired. Go back to MoneyPadi and tap \"Connect Telegram\" again.");
          return res.status(200).send("OK");
        }

        const { uid } = tokenSnap.data();
        const walletRef = db.collection("wallets").doc(uid);
        await walletRef.collection("private").doc("telegram").set({
          chatId,
          linkedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        // Reverse index so /stop can find the wallet from a chatId alone
        await db.collection("telegramChats").doc(String(chatId)).set({ uid });
        await walletRef.set({ telegramLinked: true }, { merge: true });
        await tokenRef.delete();

        await sendTelegramMessage(chatId, "You're linked! I'll remind you of your MoneyPadi code here every morning.");
      } else if (chatId && text === "/stop") {
        const chatLinkRef = db.collection("telegramChats").doc(String(chatId));
        const chatLinkSnap = await chatLinkRef.get();
        if (chatLinkSnap.exists) {
          const { uid } = chatLinkSnap.data();
          await db.collection("wallets").doc(uid).collection("private").doc("telegram").delete();
          await db.collection("wallets").doc(uid).set({ telegramLinked: false }, { merge: true });
          await chatLinkRef.delete();
          await sendTelegramMessage(chatId, "You're unlinked. Reconnect anytime from your MoneyPadi profile.");
        }
      }
      return res.status(200).send("OK");
    } catch (err) {
      console.error("telegramWebhook error:", err.response?.data || err.message);
      return res.status(200).send("OK"); // 200 always — avoid Telegram retry storms
    }
  }
);

// dailyTelegramReminder — scheduled, runs once a day. Kept deliberately
// simple/sequential with a small delay between sends; at your current
// scale this is nowhere near Telegram's rate limits, and it's easy to
// parallelize later if the user base grows.
exports.dailyTelegramReminder = onSchedule(
  { schedule: "0 7 * * *", timeZone: "Africa/Lagos", secrets: [TELEGRAM_BOT_TOKEN] },
  async () => {
    const walletsSnap = await db.collection("wallets").where("telegramLinked", "==", true).get();

    for (const walletDoc of walletsSnap.docs) {
      try {
        const telegramSnap = await walletDoc.ref.collection("private").doc("telegram").get();
        if (!telegramSnap.exists) continue;

        const wallet = walletDoc.data();
        const { chatId } = telegramSnap.data();
        const firstName = (wallet.displayName || "").split(" ")[0] || "there";

        await sendTelegramMessage(
          chatId,
          `Morning, ${firstName} ☀️ Hope today goes well.\n\nQuick reminder — your MoneyPadi code is <b>${wallet.walletCode}</b>.`
        );
        await new Promise((r) => setTimeout(r, 50));
      } catch (err) {
        console.error(`dailyTelegramReminder failed for ${walletDoc.id}:`, err.response?.data || err.message);
      }
    }
  }
);