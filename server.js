const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = "your_super_secret_key_change_this";

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./iot_dashboard.db");

// ======================
// DATABASE SETUP
// ======================
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY,
      name TEXT,
      lastSeen DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);  

  db.run(`
    CREATE TABLE IF NOT EXISTS sensor_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      deviceId INTEGER,
      solarVoltage REAL,
      solarPower REAL,
      batteryVoltage REAL,
      batteryPower REAL,
      soilMoisture REAL,
      greenValue REAL,
      temperature REAL,
      humidity REAL,
      rssi REAL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const defaultPassword = bcrypt.hashSync("admin123", 10);
  db.run(
    `INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`,
    ["admin", defaultPassword]
  );
});

const DEFAULT_DEVICE_ID = 175;
let latestDataByDevice = {};

// ======================
// AUTH MIDDLEWARE
// ======================
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

// ======================
// AUTH ROUTES
// ======================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(401).json({ error: "User not found" });

      const isValid = bcrypt.compareSync(password, user.password);
      if (!isValid) {
        return res.status(401).json({ error: "Wrong password" });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "8h" }
      );

      res.json({ token, username: user.username });
    }
  );
});

// ======================
// LATEST DATA ROUTE
// ======================
app.get("/api/latest", authenticateToken, (req, res) => {
  const deviceId = Number(req.query.device) || DEFAULT_DEVICE_ID;
  const data = latestDataByDevice[deviceId] || latestDataByDevice[DEFAULT_DEVICE_ID];
  res.json(data);
});

// ======================
// HISTORY ROUTE
// ======================
app.get("/api/history", authenticateToken, (req, res) => {
  const deviceId = Number(req.query.device) || DEFAULT_DEVICE_ID;

  db.all(
    `SELECT * FROM sensor_history
     WHERE deviceId = ?
     ORDER BY createdAt DESC
     LIMIT 20`,
    [deviceId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows.reverse());
    }
  );
});

app.get("/api/devices", authenticateToken, (req, res) => {
  db.all(
    `SELECT id, name, lastSeen
     FROM devices
     ORDER BY id ASC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});


// ======================
// IOT DATA INPUT ROUTE
// ======================
app.post("/api/iot-data", (req, res) => {
  const {
    deviceId,
    solarVoltage,
    solarPower,
    batteryVoltage,
    batteryPower,
    soilMoisture,
    greenValue,
    temperature,
    humidity,
    rssi
  } = req.body;

  if (!deviceId) {
    return res.status(400).json({ error: "deviceId is required" });
  }

  db.run(
    `INSERT INTO devices (id, name, lastSeen)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET lastSeen = CURRENT_TIMESTAMP`,
    [deviceId, `Device ${deviceId}`]
  );

  // Save as latest data
  latestDataByDevice[deviceId] = {
    solarVoltage: solarVoltage ?? 0,
    solarPower: solarPower ?? 0,
    batteryVoltage: batteryVoltage ?? 0,
    batteryPower: batteryPower ?? 0,
    soilMoisture: soilMoisture ?? 0,
    greenValue: greenValue ?? 0,
    temperature: temperature ?? 0,
    humidity: humidity ?? 0,
    rssi: rssi ?? 0
  };

  db.run(
    `INSERT INTO sensor_history
    (deviceId, solarVoltage, solarPower, batteryVoltage, batteryPower, soilMoisture, greenValue, temperature, humidity, rssi)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      deviceId,
      latestDataByDevice[deviceId].solarVoltage,
      latestDataByDevice[deviceId].solarPower,
      latestDataByDevice[deviceId].batteryVoltage,
      latestDataByDevice[deviceId].batteryPower,
      latestDataByDevice[deviceId].soilMoisture,
      latestDataByDevice[deviceId].greenValue,
      latestDataByDevice[deviceId].temperature,
      latestDataByDevice[deviceId].humidity,
      latestDataByDevice[deviceId].rssi
    ],
    (err) => {
      if (err) {
        console.error("DB insert error:", err.message);
        return res.status(500).json({ error: err.message });
      }

      console.log("📡 Received IoT data:", deviceId, latestDataByDevice[deviceId]);
      res.json({ success: true });
    }
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
  console.log("Default login: admin / admin123");
});