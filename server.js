const express = require("express");
const http = require("http");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const OWNER_PASSWORD = process.env.OWNER_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!OWNER_PASSWORD || !SESSION_SECRET) {
  console.error("Set OWNER_PASSWORD and SESSION_SECRET environment variables before starting.");
  process.exit(1);
}

const sessions = new Map();
const rooms = new Map();

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}
function ownerAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token || !sessions.has(token)) return res.status(401).json({ error: "Sign in required" });
  next();
}
app.post("/api/login", (req, res) => {
  if (!req.body || req.body.password !== OWNER_PASSWORD) {
    return res.status(401).json({ error: "Incorrect password" });
  }
  const raw = crypto.randomBytes(32).toString("hex");
  const token = raw + "." + sign(raw);
  sessions.set(token, Date.now());
  res.json({ token });
});
app.post("/api/rooms", ownerAuth, (req, res) => {
  const roomId = crypto.randomBytes(5).toString("hex");
  rooms.set(roomId, { owner: null, viewer: null, createdAt: Date.now() });
  res.json({ roomId });
});
app.post("/api/logout", ownerAuth, (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  sessions.delete(token);
  res.json({ ok: true });
});

io.use((socket, next) => {
  const { role, roomId, token } = socket.handshake.auth || {};
  if (!roomId || !rooms.has(roomId)) return next(new Error("Invalid or expired room"));
  if (role === "owner") {
    if (!token || !sessions.has(token)) return next(new Error("Owner sign-in required"));
  } else if (role !== "viewer") {
    return next(new Error("Invalid role"));
  }
  socket.data.role = role;
  socket.data.roomId = roomId;
  next();
});
io.on("connection", socket => {
  const roomId = socket.data.roomId;
  const room = rooms.get(roomId);
  socket.join(roomId);
  if (socket.data.role === "owner") room.owner = socket.id;
  else room.viewer = socket.id;

  socket.to(roomId).emit("peer-ready", { role: socket.data.role });
  socket.on("signal", payload => {
    if (!payload || !["offer", "answer", "ice"].includes(payload.type)) return;
    socket.to(roomId).emit("signal", payload);
  });
  socket.on("disconnect", () => {
    if (room.owner === socket.id) room.owner = null;
    if (room.viewer === socket.id) room.viewer = null;
    socket.to(roomId).emit("peer-left");
  });
});

server.listen(PORT, () => console.log(`X EYE server listening on ${PORT}`));
