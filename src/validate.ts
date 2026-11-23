import type { Context } from "hono";
import type { z } from "zod";
import { HttpError } from "./errors";

/** Parse a JSON body and validate it with a zod schema. Anything unexpected → 400. */
export async function readJson<S extends z.ZodType>(c: Context, schema: S): Promise<z.infer<S>> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    throw new HttpError(400, "invalid_json");
  }
  return schema.parse(raw);
}

/** Validate query-string params with a zod schema. */
export function readQuery<S extends z.ZodType>(c: Context, schema: S): z.infer<S> {
  return schema.parse(c.req.query());
}
