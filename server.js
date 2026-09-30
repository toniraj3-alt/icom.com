const express = require("express");
const multer = require("multer");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const COMPLAINT_PASSWORDS = Array.from({ length: 10 }, (_, i) => process.env[`COMPLAINT_PASSWORD_${i + 1}`] || "").filter(Boolean);
const sessions = new Map();
const loginAttempts = new Map();
const usedComplaintNumbers = new Set();
const PRIVATE_COMPLAINT_PAGE = path.join(__dirname, "private", "complaint.html");
const upload = multer({
  dest: path.join(__dirname, "uploads"),
  limits: { fileSize: 8 * 1024 * 1024 }
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || "false") === "true",
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

app.use(express.urlencoded({ extended: false }));

function getSessionToken(req) {
  return req.headers.cookie?.match(/(?:^|;\s*)icom_session=([^;]+)/)?.[1];
}

function authRequired(req, res, next) {
  const token = getSessionToken(req);
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    res.setHeader("Cache-Control", "no-store");
    return res.redirect("/login.html");
  }
  req.user = session;
  next();
}

app.get("/complaint.html", authRequired, (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.sendFile(PRIVATE_COMPLAINT_PAGE);
});

app.get("/api/auth/status", (req, res) => {
  const token = getSessionToken(req);
  const session = token && sessions.get(token);
  const authenticated = !!(session && session.expiresAt >= Date.now());
  if (!authenticated && token) sessions.delete(token);
  res.setHeader("Cache-Control", "no-store");
  res.json({ authenticated });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const recent = (loginAttempts.get(ip) || []).filter(t => now - t < 10 * 60 * 1000);
  if (recent.length >= 10) {
    return res.status(429).json({ ok:false, message:"Too many login attempts. Please try again later." });
  }
  recent.push(now);
  loginAttempts.set(ip, recent);

  if (!COMPLAINT_PASSWORDS.length) {
    return res.status(503).json({ ok:false, message:"Complaint login passwords are not configured on the server." });
  }
  if (!String(username || "").trim() || !COMPLAINT_PASSWORDS.includes(String(password || ""))) {
    return res.status(401).json({ ok:false, message:"Invalid username or password." });
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    username: String(username).trim(),
    createdAt: now,
    expiresAt: now + 8 * 60 * 60 * 1000
  });

  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `icom_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
  res.setHeader("Cache-Control", "no-store");
  res.json({ ok:true });
});

app.post("/api/logout", (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "icom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  res.setHeader("Cache-Control", "no-store");
  res.json({ ok:true });
});

app.post("/api/complaints", authRequired, upload.single("machineImage"), async (req, res) => {
  try {
    const required = [
      "branchName","branchCode","region","contactPerson","mobile",
      "email","machine","address","complaint","additionalInfo"
    ];
    for (const key of required) {
      if (!req.body[key] || !String(req.body[key]).trim()) {
        return res.status(400).send("Missing required field: " + key);
      }
    }
    if (!req.file) return res.status(400).send("Machine image is required.");

    const {
      branchName, branchCode, region, contactPerson,
      mobile, email, machine, address, complaint, additionalInfo
    } = req.body;

    let complaintNumber;
    do {
      const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const digits = "0123456789";
      complaintNumber =
        letters[Math.floor(Math.random() * letters.length)] +
        letters[Math.floor(Math.random() * letters.length)] +
        Array.from({length: 6}, () => digits[Math.floor(Math.random() * digits.length)]).join("");
    } while (usedComplaintNumbers.has(complaintNumber));
    usedComplaintNumbers.add(complaintNumber);

    const text = `
ICOM COUNT CUSTOMER COMPLAINT

Complaint Number: ${complaintNumber}

Branch Name: ${branchName}
Branch Code: ${branchCode}
Region: ${region}
Contact Person: ${contactPerson}
Mobile Number: ${mobile}
Customer Email: ${email}
Machine / Product: ${machine}

Address:
${address}

Complaint Details:
${complaint}

Additional Information:
${additionalInfo}
`;

    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: "icomcount@outlook.com",
      replyTo: email,
      subject: `ICOM COUNT Complaint ${complaintNumber} - ${machine}`,
      text,
      attachments: [{ filename: req.file.originalname || "machine-image", path: req.file.path }]
    });

    // Remove uploaded file after the email is accepted by SMTP.
    fs.unlink(req.file.path, () => {});
    res.setHeader("Cache-Control", "no-store");
    res.json({ ok: true, complaintNumber });
  } catch (err) {
    console.error(err);
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(500).send("Unable to submit complaint.");
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt < now) sessions.delete(token);
  }
  for (const [ip, attempts] of loginAttempts) {
    const fresh = attempts.filter(t => now - t < 10 * 60 * 1000);
    if (fresh.length) loginAttempts.set(ip, fresh);
    else loginAttempts.delete(ip);
  }
}, 15 * 60 * 1000).unref();

app.listen(PORT, () => console.log(`ICOM COUNT server running on port ${PORT}`));
