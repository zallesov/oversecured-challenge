import PocketBase from "pocketbase";

const POCKETBASE_URL = process.env.POCKETBASE_URL ?? "http://localhost:8090";

export type AuthUser = { id: string; email: string };

// Module-level singleton admin client
let _adminPb: PocketBase | null = null;

/**
 * Cached PocketBase client authenticated as superuser.
 * Re-authenticates if the cached token is invalid.
 */
export async function adminPb(): Promise<PocketBase> {
  const email = process.env.POCKETBASE_ADMIN_EMAIL;
  const password = process.env.POCKETBASE_ADMIN_PASSWORD;

  if (!email || !password) {
    throw new Error(
      "POCKETBASE_ADMIN_EMAIL and POCKETBASE_ADMIN_PASSWORD are required",
    );
  }

  if (!_adminPb) {
    _adminPb = new PocketBase(POCKETBASE_URL);
  }

  if (!_adminPb.authStore.isValid) {
    await _adminPb
      .collection("_superusers")
      .authWithPassword(email, password);
  }

  return _adminPb;
}

/**
 * Validate a PocketBase user auth token.
 * Resolves to the user record, rejects if the token is invalid.
 */
export async function verifyUserToken(token: string): Promise<AuthUser> {
  const pb = new PocketBase(POCKETBASE_URL);
  pb.authStore.save(token, null);
  const result = await pb.collection("users").authRefresh();
  return {
    id: result.record.id,
    email: result.record.email as string,
  };
}
