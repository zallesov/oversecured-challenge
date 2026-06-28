import type { NextFunction, Request, RequestHandler, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const PASSWORD_COST = 12;

export type AuthUser = {
  id: string;
  email: string;
};

export type AuthenticatedRequest = Request & {
  user?: AuthUser;
};

type TokenPayload = jwt.JwtPayload & {
  sub: string;
  email: string;
};

function jwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is required");
  }
  return secret;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, PASSWORD_COST);
}

export async function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  return bcrypt.compare(password, passwordHash);
}

export function signAuthToken(user: AuthUser): string {
  const options: jwt.SignOptions = {
    subject: user.id,
    expiresIn: (process.env.JWT_EXPIRES_IN ??
      "7d") as jwt.SignOptions["expiresIn"],
  };

  return jwt.sign(
    {
      email: user.email,
    },
    jwtSecret(),
    options,
  );
}

export function verifyAuthToken(token: string): AuthUser {
  const decoded = jwt.verify(token, jwtSecret());

  if (
    typeof decoded !== "object" ||
    decoded === null ||
    typeof (decoded as TokenPayload).sub !== "string" ||
    typeof (decoded as TokenPayload).email !== "string"
  ) {
    throw new Error("Invalid auth token");
  }

  const payload = decoded as TokenPayload;
  return {
    id: payload.sub,
    email: payload.email,
  };
}

export const requireAuth: RequestHandler = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
) => {
  const header = req.header("authorization");
  const match = header?.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    res.status(401).json({ error: "Missing bearer token" });
    return;
  }

  try {
    req.user = verifyAuthToken(match[1]);
    next();
  } catch {
    res.status(401).json({ error: "Invalid bearer token" });
  }
};
