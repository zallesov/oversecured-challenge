import type { NextFunction, Request, RequestHandler, Response } from "express";

import { verifyUserToken } from "./pb.js";
import type { AuthUser } from "./pb.js";

export type { AuthUser };

export type AuthenticatedRequest = Request & {
  user?: AuthUser;
};

export const requireAuth: RequestHandler = async (
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
    req.user = await verifyUserToken(match[1]);
    next();
  } catch {
    res.status(401).json({ error: "Invalid bearer token" });
  }
};
