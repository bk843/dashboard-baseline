import type { BaseConfig } from "./config";

export type Role = "viewer" | "admin";

export interface User {
  email: string;
  role: Role;
}

export interface BaseBindings {
  ASSETS: Fetcher;
  RL_API: RateLimit;
  [key: string]: unknown;
}

/** Hono env type for every dashboard. Extend `C` with your config and `B` with your bindings. */
export interface SecureEnv<C extends BaseConfig = BaseConfig, B extends BaseBindings = BaseBindings> {
  Bindings: B;
  Variables: {
    config: C;
    user: User;
    requestId: string;
  };
}
