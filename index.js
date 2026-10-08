import express from "express";
import helmet from "helmet";
import bcrypt from "bcryptjs";

import watchlistRoutes from "./routes/watchlist.js";
import { findByUsername } from "./utils/db.js";
import { signToken } from "./utils/jwt.js";

const PORT = process.env.PORT || 3000;
const app = express();

app.use(helmet());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Family Movie Watchlist API");
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required",
    });
  }

  const user = findByUsername(username);

  if (!user) {
    return res.status(401).json({
      error: "Invalid credentials",
    });
  }

  const passwordValid = await bcrypt.compare(password, user.passwordHash);

  if (!passwordValid) {
    return res.status(401).json({
      error: "Invalid credentials",
    });
  }

  const token = signToken({
    id: user.id,
    username: user.username,
    role: user.role,
  });

  return res.status(200).json({ token });
});

app.use("/api/watchlist", watchlistRoutes);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}...`);
});
