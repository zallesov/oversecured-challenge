import { Router, type NextFunction, type Request, type Response } from "express";
import { randomUUID } from "node:crypto";

import {
  hashPassword,
  requireAuth,
  signAuthToken,
  verifyPassword,
  type AuthenticatedRequest,
} from "../auth.js";
import { query } from "../db.js";

type UserRow = {
  id: string;
  email: string;
  password_hash: string;
};

const router = Router();

function asyncHandler(
  handler: (req: Request, res: Response) => Promise<void>,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    handler(req, res).catch(next);
  };
}

function parseCredentials(body: unknown): { email: string; password: string } | null {
  if (typeof body !== "object" || body === null) {
    return null;
  }
  const { email, password } = body as Record<string, unknown>;
  if (typeof email !== "string" || typeof password !== "string") {
    return null;
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (!normalizedEmail.includes("@") || password.length < 8) {
    return null;
  }
  return { email: normalizedEmail, password };
}

router.post(
  "/register",
  asyncHandler(async (req, res) => {
    const credentials = parseCredentials(req.body);
    if (!credentials) {
      res.status(400).json({ error: "Email and password are required" });
      return;
    }

    const user = {
      id: randomUUID(),
      email: credentials.email,
    };

    try {
      await query(
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
        [user.id, user.email, await hashPassword(credentials.password)],
      );
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "23505"
      ) {
        res.status(409).json({ error: "Email is already registered" });
        return;
      }
      throw error;
    }

    res.status(201).json({
      user,
      token: signAuthToken(user),
    });
  }),
);

router.post(
  "/login",
  asyncHandler(async (req, res) => {
    const credentials = parseCredentials(req.body);
    if (!credentials) {
      res.status(400).json({ error: "Email and password are required" });
      return;
    }

    const result = await query<UserRow>(
      "SELECT id, email, password_hash FROM users WHERE email = $1",
      [credentials.email],
    );
    const user = result.rows[0];

    if (!user || !(await verifyPassword(credentials.password, user.password_hash))) {
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    const authUser = {
      id: user.id,
      email: user.email,
    };

    res.json({
      user: authUser,
      token: signAuthToken(authUser),
    });
  }),
);

router.get("/me", requireAuth, (req: AuthenticatedRequest, res) => {
  res.json(req.user);
});

export default router;
