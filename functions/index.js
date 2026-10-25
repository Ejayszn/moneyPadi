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


// ---- Admin + charge notifications ----
const ADMIN_EMAILS = ["emmyogs007@gmail.com"]; // must be a verified email

function assertAdmin(request) {
  const t = request.auth?.token;
  if (!t || !t.email_verified || !ADMIN_EMAILS.includes((t.email || "").toLowerCase())) {
    throw new HttpsError("permission-denied", "Admins only.");
  }
}

const escHtml = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

// Tells the student about every completed charge, by Telegram only.
async function notifyCharge({ studentUid, studentEmail, vendorName, amount }) {
  const amountText = `₦${(amount / 100).toLocaleString("en-NG")}`;
  const when = new Date().toLocaleString("en-NG", {
    timeZone: "Africa/Lagos", day: "numeric", month: "short", hour: "numeric", minute: "2-digit",
  });
  try {
    const tg = await db.collection("wallets").doc(studentUid).collection("private").doc("telegram").get();
    if (tg.exists) {
      await sendTelegramMessage(
        tg.data().chatId,
        `<b>${amountText}</b> was charged to your saved card by <b>${escHtml(vendorName)}</b> (${when}).\n\nNot you? Contact MoneyPadi support right away.`
      );
    }
  } catch (err) {
    console.error("notifyCharge telegram failed:", err.response?.data || err.message);
    // The student blocked the bot: stop charging them until they reconnect
    if (err.response?.status === 403) {
      await db.collection("wallets").doc(studentUid).set({ telegramLinked: false }, { merge: true });
    }
  }
}

exports.adminOverview = onCall(async (request) => {
  assertAdmin(request);
  const [txSnap, walletSnap, disputeSnap] = await Promise.all([
    db.collection("transactions").orderBy("createdAt", "desc").limit(200).get(),
    db.collection("wallets").limit(300).get(),
    db.collection("disputes").orderBy("createdAt", "desc").limit(100).get(),
  ]);
  const transactions = txSnap.docs
    .map((d) => ({ id: d.id, ...d.data() }))
    .filter((x) => x.payerUid) // charges only, skips old topups/withdrawals
    .map((x) => ({
      id: x.id,
      payerName: x.payerName || "",
      vendorName: x.vendorName || "",
      amount: x.amount || 0,
      status: x.status || "",
      createdAt: x.createdAt?.toMillis?.() || 0,
      evidence: x.evidence || null,
      gatewayResponse: x.gatewayResponse || "",
      reported: !!x.reported,
    }));
  const people = walletSnap.docs.map((d) => {
    const w = d.data();
    return {
      uid: d.id,
      name: w.displayName || "",
      email: w.email || "",
      code: w.walletCode || "",
      card: w.cardOnFile?.last4 || "",
      payout: w.bankOnFile?.bankName || "",
      vendorApproved: !!w.vendorApproved,
      frozen: !!w.frozen,
    };
  });
  const disputes = disputeSnap.docs.map((d) => {
    const x = d.data();
    return {
      id: d.id,
      txId: x.txId || d.id,
      payerName: x.payerName || "",
      vendorName: x.vendorName || "",
      vendorUid: x.vendorUid || "",
      amount: x.amount || 0,
      note: x.note || "",
      status: x.status || "open",
      createdAt: x.createdAt?.toMillis?.() || 0,
    };
  });
  return { transactions, people, disputes };
});

exports.adminSetFlags = onCall(async (request) => {
  assertAdmin(request);
  const { uid, vendorApproved, frozen } = request.data || {};
  if (typeof uid !== "string" || !uid) throw new HttpsError("invalid-argument", "Missing user.");
  const update = {};
  if (typeof vendorApproved === "boolean") update.vendorApproved = vendorApproved;
  if (typeof frozen === "boolean") update.frozen = frozen;
  if (!Object.keys(update).length) throw new HttpsError("invalid-argument", "Nothing to change.");
  await db.collection("wallets").doc(uid).set(update, { merge: true });
  await db.collection("adminLog").add({
    by: request.auth.uid, uid, update, at: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { success: true };
});

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
const SINGLE_TX_LIMIT = 200000;     // ₦2,000 per charge (pilot)
const DAILY_LIMIT = 500000;         // ₦5,000 per student per day (pilot)
const VENDOR_DAILY_LIMIT = 3000000; // ₦30,000 per vendor per day (pilot), change to taste
const VENDOR_MAX_BAD_PINS = 10;     // wrong PINs typed on one vendor's device in a day before auto-freeze
const MAX_PIN_ATTEMPTS = 4;
const naira0 = (kobo) => "₦" + (kobo / 100).toLocaleString("en-NG");

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
// Who pays Paystack's fee on each charge: "subaccount" = the vendor,
// "account" = MoneyPadi. Your call, decide before launch.
const FEE_BEARER = "subaccount";

exports.chargeWallet = onCall({ secrets: [PAYSTACK_SECRET, TELEGRAM_BOT_TOKEN] }, async (request) => {
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
    throw new HttpsError("failed-precondition", `This exceeds the ${naira0(SINGLE_TX_LIMIT)} per-transaction limit.`);
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

  const studentCardRef = studentWalletRef.collection("private").doc("card");
  const vendorBankRef = vendorWalletRef.collection("private").doc("bank");
  const vendorSecurityRef = vendorWalletRef.collection("private").doc("security");
  const systemRef = db.collection("config").doc("system");

  const reserved = await db.runTransaction(async (t) => {
    const [securitySnap, studentWalletSnap, vendorWalletSnap, cardSnap, vendorBankSnap, vendorSecSnap, systemSnap] = await Promise.all([
      t.get(studentSecurityRef),
      t.get(studentWalletRef),
      t.get(vendorWalletRef),
      t.get(studentCardRef),
      t.get(vendorBankRef),
      t.get(vendorSecurityRef),
      t.get(systemRef),
    ]);
    if (systemSnap.exists && systemSnap.data().chargingPaused === true) {
      throw new HttpsError("unavailable", "Charging is paused for now. Try again later.");
    }
    const todayKey = new Date().toISOString().slice(0, 10);
    const vendorSec = vendorSecSnap.exists ? vendorSecSnap.data() : {};

    if (!securitySnap.exists || !studentWalletSnap.exists || !vendorWalletSnap.exists) {
      throw new HttpsError("not-found", "Wallet not fully set up.");
    }
    const security = securitySnap.data();
    const studentWallet = studentWalletSnap.data();
    const vendorWallet = vendorWalletSnap.data();

    if (!vendorWallet.vendorApproved) {
      throw new HttpsError("permission-denied", "Your vendor account isn't approved yet. Contact MoneyPadi.");
    }
    if (vendorWallet.frozen || studentWallet.frozen) {
      throw new HttpsError("permission-denied", "This account is frozen. Contact MoneyPadi.");
    }
    if (!studentWallet.telegramLinked) {
      throw new HttpsError("failed-precondition", "This student hasn't connected Telegram yet. They need to open MoneyPadi and connect it first.");
    }
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
      // Count wrong PINs per vendor per day; freeze a vendor who keeps guessing
      const badPins = (vendorSec.badPinDate === todayKey ? (vendorSec.badPinCount || 0) : 0) + 1;
      t.set(vendorSecurityRef, { badPinDate: todayKey, badPinCount: badPins }, { merge: true });
      if (badPins >= VENDOR_MAX_BAD_PINS) {
        t.set(vendorWalletRef, { frozen: true, frozenReason: "Too many wrong PINs" }, { merge: true });
      }
      // Return instead of throwing: a throw inside a Firestore transaction
      // rolls it back, so the failed-attempt count would never be saved.
      return {
        pinError:
          attempts >= MAX_PIN_ATTEMPTS
            ? "Wrong PIN. This wallet is now locked."
            : `Wrong PIN. ${MAX_PIN_ATTEMPTS - attempts} attempt(s) left.`,
      };
    }

    // Daily cap resets automatically on a new calendar day
    const todayStr = new Date().toISOString().slice(0, 10);
    const dailySpent = security.dailySpentDate === todayStr ? (security.dailySpent || 0) : 0;
    if (dailySpent + amt > DAILY_LIMIT) {
      throw new HttpsError("failed-precondition", `This would exceed the ${naira0(DAILY_LIMIT)} daily limit.`);
    }
    const vendorToday = vendorSec.vendorDailyDate === todayKey ? (vendorSec.vendorDailyTotal || 0) : 0;
    if (vendorToday + amt > VENDOR_DAILY_LIMIT) {
      throw new HttpsError("failed-precondition", "This vendor has reached today's limit. Try again tomorrow.");
    }
    if (!cardSnap.exists) {
      throw new HttpsError("failed-precondition", "This student hasn't added a card yet.");
    }
    if (!vendorBankSnap.exists || !vendorBankSnap.data().subaccountCode) {
      throw new HttpsError("failed-precondition", "Link your payout account first so you can receive payments.");
    }

    // Reserve the daily allowance and record the charge as pending.
    // The Paystack call happens AFTER this transaction, because network
    // calls don't belong inside a Firestore transaction (it can retry).
    t.set(
      studentSecurityRef,
      { failedPinAttempts: 0, dailySpent: dailySpent + amt, dailySpentDate: todayStr },
      { merge: true }
    );
    t.set(vendorSecurityRef, { vendorDailyDate: todayKey, vendorDailyTotal: vendorToday + amt }, { merge: true });
    t.set(txRef, {
      payerUid: studentUid,
      payerName: studentWallet.displayName || "",
      vendorUid: vendorUid,
      vendorName: vendorWallet.displayName || "",
      amount: amt,
      status: "pending",
      evidence: {
        pinVerified: true,
        ip: request.rawRequest?.ip || "",
        userAgent: String(request.rawRequest?.headers?.["user-agent"] || "").slice(0, 200),
        cardLast4: cardSnap.data().last4 || "",
      },
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      authorizationCode: cardSnap.data().authorizationCode,
      email: studentWallet.email,
      subaccountCode: vendorBankSnap.data().subaccountCode,
      todayStr,
    };
  });

  if (reserved.pinError) {
    throw new HttpsError("permission-denied", reserved.pinError);
  }

  const paystackHeaders = { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` };
  try {
    const res = await axios.post(
      `${PAYSTACK_BASE}/transaction/charge_authorization`,
      {
        authorization_code: reserved.authorizationCode,
        email: reserved.email,
        amount: amt,
        currency: "NGN",
        reference: txRef.id, // doubles as the idempotency key
        subaccount: reserved.subaccountCode,
        bearer: FEE_BEARER,
        metadata: { purpose: "charge" },
      },
      { headers: paystackHeaders, timeout: 20000 }
    );
    if (res.data?.data?.status !== "success") {
      throw new Error(res.data?.gateway_response || "declined");
    }
    await txRef.set(
      { status: "completed", gatewayResponse: res.data?.data?.gateway_response || "" },
      { merge: true }
    );
    const doneTx = (await txRef.get()).data();
    await notifyCharge({
      studentUid,
      studentEmail: reserved.email,
      vendorName: doneTx.vendorName || "a vendor",
      amount: amt,
    });
    return { success: true, txId: txRef.id };
  } catch (err) {
    console.error("chargeWallet charge error:", err.response?.data || err.message);

    // If we got no clear answer (timeout etc.), ask Paystack before assuming failure
    try {
      const check = await axios.get(`${PAYSTACK_BASE}/transaction/verify/${txRef.id}`, {
        headers: paystackHeaders,
        timeout: 15000,
      });
      if (check.data?.data?.status === "success") {
        await txRef.set({ status: "completed" }, { merge: true });
        const lateTx = (await txRef.get()).data();
        await notifyCharge({
          studentUid,
          studentEmail: reserved.email,
          vendorName: lateTx.vendorName || "a vendor",
          amount: amt,
        });
        return { success: true, txId: txRef.id };
      }
    } catch (verifyErr) {
      // not found on Paystack's side means it never went through
    }

    // Give the reserved daily allowance back and mark the charge failed
    await db.runTransaction(async (t) => {
      const [s, v] = await Promise.all([t.get(studentSecurityRef), t.get(vendorSecurityRef)]);
      const d = s.data() || {};
      const vd = v.data() || {};
      if (d.dailySpentDate === reserved.todayStr) {
        t.set(studentSecurityRef, { dailySpent: Math.max(0, (d.dailySpent || 0) - amt) }, { merge: true });
      }
      if (vd.vendorDailyDate === reserved.todayStr) {
        t.set(vendorSecurityRef, { vendorDailyTotal: Math.max(0, (vd.vendorDailyTotal || 0) - amt) }, { merge: true });
      }
    });
    await txRef.set({ status: "failed" }, { merge: true });
    throw new HttpsError(
      "failed-precondition",
      "The card was declined. Ask the student to try again or use another card."
    );
  }
});

// Single webhook endpoint — Paystack only allows one URL per account,
// so this dispatches on event type instead of using separate functions.
exports.paystackWebhook = onRequest({ secrets: [PAYSTACK_SECRET, TELEGRAM_BOT_TOKEN] }, async (req, res) => {
  const hash = crypto
    .createHmac("sha512", PAYSTACK_SECRET.value())
    .update(req.rawBody)
    .digest("hex");
  if (hash !== req.headers["x-paystack-signature"]) {
    return res.status(401).send("Invalid signature");
  }

  const event = req.body;
  try {
    if (event.event === "charge.success") {
      if (event.data.metadata?.purpose === "add_card") {
        await saveCardIfPending(event.data.reference, event.data.authorization);
      } else if (event.data.metadata?.purpose === "charge") {
        const chargeTxRef = db.collection("transactions").doc(event.data.reference);
        const chargeTxSnap = await chargeTxRef.get();
        if (chargeTxSnap.exists && chargeTxSnap.data().status === "pending") {
          await chargeTxRef.set({ status: "completed" }, { merge: true });
          const ctx = chargeTxSnap.data();
          const payerWallet = (await db.collection("wallets").doc(ctx.payerUid).get()).data() || {};
          await notifyCharge({
            studentUid: ctx.payerUid,
            studentEmail: payerWallet.email,
            vendorName: ctx.vendorName || "a vendor",
            amount: ctx.amount,
          });
        }
      }
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
    // Subaccount = the vendor's settlement destination. percentage_charge 0
    // means the platform keeps nothing; the vendor gets the full payment
    // minus Paystack's fee (see FEE_BEARER below).
    const res = await axios.post(
      `${PAYSTACK_BASE}/subaccount`,
      {
        business_name: accountName,
        settlement_bank: bankCode,
        account_number: accountNumber,
        percentage_charge: 0,
      },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` }, timeout: 15000 }
    );
    const subaccountCode = res.data.data.subaccount_code;
    const last4 = accountNumber.slice(-4);

    await db.collection("wallets").doc(uid).collection("private").doc("bank").set({
      subaccountCode, bankName, accountName, last4,
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

// ============================================================
// CARD ON FILE: student saves a card once. Paystack's hosted
// checkout collects the card (card details never touch our
// servers). We only keep the reusable authorization code.
// ============================================================
const CARD_SETUP_AMOUNT = 5000; // N50 in kobo, small first charge that yields a reusable authorization
const ALLOWED_RETURN_ORIGINS = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "https://ejayszn.github.io",
];

exports.initiateAddCard = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  let returnUrl;
  try {
    const parsed = new URL(request.data?.returnUrl);
    if (!ALLOWED_RETURN_ORIGINS.includes(parsed.origin)) throw new Error("bad origin");
    returnUrl = parsed.origin + parsed.pathname;
  } catch {
    throw new HttpsError("invalid-argument", "Invalid return URL.");
  }

  const userRecord = await admin.auth().getUser(uid);
  const setupRef = db.collection("cardSetups").doc();
  await setupRef.set({
    uid,
    status: "pending",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  try {
    const res = await axios.post(
      `${PAYSTACK_BASE}/transaction/initialize`,
      {
        email: userRecord.email,
        amount: CARD_SETUP_AMOUNT,
        currency: "NGN",
        reference: setupRef.id,
        channels: ["card"],
        callback_url: returnUrl,
        metadata: { purpose: "add_card", uid },
      },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` }, timeout: 15000 }
    );
    return { reference: setupRef.id, authorizationUrl: res.data.data.authorization_url };
  } catch (err) {
    console.error("initiateAddCard error:", err.response?.data || err.message);
    throw new HttpsError("internal", "Couldn't start card setup. Try again.");
  }
});

// Shared idempotent save, called by both verifyAddCard (client, after
// the redirect back) and the webhook (server push). Whichever arrives
// first saves the card, the other becomes a no-op.
async function saveCardIfPending(reference, authorization) {
  const setupRef = db.collection("cardSetups").doc(reference);

  return db.runTransaction(async (t) => {
    const snap = await t.get(setupRef);
    if (!snap.exists) return { notFound: true };
    const setup = snap.data();
    if (setup.status !== "pending") return { alreadyProcessed: true };

    if (!authorization?.reusable) {
      t.set(setupRef, { status: "failed", reason: "not_reusable" }, { merge: true });
      return { notReusable: true };
    }

    const card = {
      last4: authorization.last4 || "",
      brand: (authorization.brand || authorization.card_type || "").trim(),
      bank: authorization.bank || "",
      expMonth: authorization.exp_month || "",
      expYear: authorization.exp_year || "",
    };
    const walletRef = db.collection("wallets").doc(setup.uid);
    t.set(walletRef.collection("private").doc("card"), {
      authorizationCode: authorization.authorization_code,
      signature: authorization.signature || "",
      ...card,
    });
    t.set(walletRef, { cardOnFile: card }, { merge: true });
    t.set(setupRef, { status: "completed", completedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return { saved: true };
  });
}

exports.verifyAddCard = onCall({ secrets: [PAYSTACK_SECRET] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const reference = request.data?.reference;
  if (!reference) throw new HttpsError("invalid-argument", "Missing reference.");

  const setupSnap = await db.collection("cardSetups").doc(reference).get();
  if (!setupSnap.exists || setupSnap.data().uid !== uid) {
    throw new HttpsError("not-found", "Card setup not found.");
  }

  try {
    const verifyRes = await axios.get(`${PAYSTACK_BASE}/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` },
      timeout: 15000,
    });
    const tx = verifyRes.data?.data;

    if (tx.status !== "success") return { saved: false, status: tx.status };
    if (tx.amount !== CARD_SETUP_AMOUNT || tx.currency !== "NGN") {
      throw new HttpsError("failed-precondition", "Payment details don't match.");
    }

    const result = await saveCardIfPending(reference, tx.authorization);
    if (result.notReusable) {
      throw new HttpsError("failed-precondition", "This card can't be saved. Try a different card.");
    }
    return { saved: true };
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("verifyAddCard error:", err.response?.data || err.message);
    throw new HttpsError("internal", "Couldn't verify your card.");
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

// ============================================================
// REMOVE CARD, REPORT A CHARGE, RECONCILIATION
// ============================================================

async function notifyAdmin(text) {
  try {
    for (const email of ADMIN_EMAILS) {
      const u = await admin.auth().getUserByEmail(email);
      const tg = await db.collection("wallets").doc(u.uid).collection("private").doc("telegram").get();
      if (tg.exists) await sendTelegramMessage(tg.data().chatId, text);
    }
  } catch (err) {
    console.error("notifyAdmin failed:", err.response?.data || err.message);
  }
}

// Student removes their saved card. Vendors can't charge them until they add one again.
exports.removeCard = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");
  const walletRef = db.collection("wallets").doc(uid);
  await walletRef.collection("private").doc("card").delete();
  await walletRef.set({ cardOnFile: admin.firestore.FieldValue.delete() }, { merge: true });
  return { success: true };
});

// Student reports a completed charge they don't recognise. Two open reports
// against the same vendor freeze that vendor automatically.
exports.reportCharge = onCall({ secrets: [TELEGRAM_BOT_TOKEN] }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "You need to be logged in.");

  const txId = request.data?.txId;
  const note = String(request.data?.note || "").slice(0, 300);
  if (typeof txId !== "string" || !txId) throw new HttpsError("invalid-argument", "Missing charge.");

  const txRef = db.collection("transactions").doc(txId);
  const txSnap = await txRef.get();
  if (!txSnap.exists || txSnap.data().payerUid !== uid) {
    throw new HttpsError("not-found", "Charge not found.");
  }
  const tx = txSnap.data();
  if (tx.status !== "completed") throw new HttpsError("failed-precondition", "Only completed charges can be reported.");
  if (tx.reported) throw new HttpsError("already-exists", "You've already reported this charge.");

  await db.collection("disputes").doc(txId).set({
    txId,
    payerUid: uid,
    payerName: tx.payerName || "",
    vendorUid: tx.vendorUid,
    vendorName: tx.vendorName || "",
    amount: tx.amount,
    note,
    status: "open",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  await txRef.set({ reported: true }, { merge: true });

  const open = await db.collection("disputes")
    .where("vendorUid", "==", tx.vendorUid)
    .where("status", "==", "open")
    .get();
  let frozen = false;
  if (open.size >= 2) {
    await db.collection("wallets").doc(tx.vendorUid).set(
      { frozen: true, frozenReason: "Multiple reports" }, { merge: true }
    );
    frozen = true;
  }

  await notifyAdmin(
    `<b>Charge reported</b>\n${escHtml(tx.payerName || "A student")} reported ${escHtml(tx.vendorName || "a vendor")} ` +
    `(₦${(tx.amount / 100).toLocaleString("en-NG")}).\n` +
    (note ? `Note: ${escHtml(note)}\n` : "") +
    (frozen ? "The vendor now has 2+ open reports and was frozen automatically." : "Check the Reports tab on the admin page.")
  );
  return { success: true };
});

exports.adminCloseDispute = onCall(async (request) => {
  assertAdmin(request);
  const id = request.data?.id;
  if (typeof id !== "string" || !id) throw new HttpsError("invalid-argument", "Missing report.");
  await db.collection("disputes").doc(id).set(
    { status: "closed", closedBy: request.auth.uid, closedAt: admin.firestore.FieldValue.serverTimestamp() },
    { merge: true }
  );
  return { success: true };
});

// Every 15 minutes: charges stuck on "pending" for 10+ minutes get settled
// against what Paystack says, and the daily limit they reserved is given back.
exports.reconcilePendingCharges = onSchedule(
  { schedule: "every 15 minutes", timeZone: "Africa/Lagos", secrets: [PAYSTACK_SECRET, TELEGRAM_BOT_TOKEN] },
  async () => {
    const cutoff = Date.now() - 10 * 60 * 1000;
    const snap = await db.collection("transactions").where("status", "==", "pending").get();

    for (const doc of snap.docs) {
      const tx = doc.data();
      if (!tx.payerUid || !tx.vendorUid) continue; // charges only
      if ((tx.createdAt?.toMillis?.() || 0) > cutoff) continue;

      let outcome = null;
      try {
        const r = await axios.get(`${PAYSTACK_BASE}/transaction/verify/${doc.id}`, {
          headers: { Authorization: `Bearer ${PAYSTACK_SECRET.value()}` },
          timeout: 15000,
        });
        const s = r.data?.data?.status;
        if (s === "success") outcome = "completed";
        else if (["failed", "abandoned", "reversed"].includes(s)) outcome = "failed";
      } catch (err) {
        const code = err.response?.status;
        if (code === 400 || code === 404) outcome = "failed"; // Paystack never saw it
        else continue; // network trouble: try again next run
      }
      if (!outcome) continue;

      let changed = false;
      const day = new Date(tx.createdAt.toMillis()).toISOString().slice(0, 10);
      const studentSecRef = db.collection("wallets").doc(tx.payerUid).collection("private").doc("security");
      const vendorSecRef = db.collection("wallets").doc(tx.vendorUid).collection("private").doc("security");

      await db.runTransaction(async (t) => {
        const fresh = await t.get(doc.ref);
        if (!fresh.exists || fresh.data().status !== "pending") return;
        let s = {}, v = {};
        if (outcome === "failed") {
          const [sSnap, vSnap] = await Promise.all([t.get(studentSecRef), t.get(vendorSecRef)]);
          s = sSnap.data() || {};
          v = vSnap.data() || {};
        }
        if (outcome === "failed") {
          if (s.dailySpentDate === day) {
            t.set(studentSecRef, { dailySpent: Math.max(0, (s.dailySpent || 0) - tx.amount) }, { merge: true });
          }
          if (v.vendorDailyDate === day) {
            t.set(vendorSecRef, { vendorDailyTotal: Math.max(0, (v.vendorDailyTotal || 0) - tx.amount) }, { merge: true });
          }
        }
        t.set(doc.ref, { status: outcome, reconciled: true }, { merge: true });
        changed = true;
      });

      if (changed && outcome === "completed") {
        await notifyCharge({
          studentUid: tx.payerUid,
          studentEmail: "",
          vendorName: tx.vendorName || "a vendor",
          amount: tx.amount,
        });
      }
    }
  }
);