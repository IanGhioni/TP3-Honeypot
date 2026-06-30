import { createAdminClient } from "@/utils/supabase/admin";
import { classifyInput, type AttackType } from "@/utils/honeypot/classify";
import type { Fingerprint } from "@/utils/honeypot/fingerprint";

export type EventType =
  | "login_attempt"
  | "scanner_hit"
  | "api_probe"
  | "file_bait";

/** Datos específicos del señuelo que el caller ya conoce. */
export interface EventDetails {
  event_type: EventType;
  /** Ruta efectivamente solicitada (puede venir de un header de rewrite). */
  path?: string;
  username?: string;
  password?: string;
  /** Body / query crudos capturados, se guardan como jsonb. */
  payload?: unknown;
  /** Fingerprint del cliente (resolución, timezone, canvas hash, etc.). */
  fingerprint?: Fingerprint;
  /** Tiempo en página en milisegundos (señuelo de login). */
  timing_ms?: number;
  /** Strings extra a pasar por el clasificador de inyecciones. */
  extraClassified?: Array<string | undefined | null>;
}

/** Primer valor de un header tipo lista separada por comas. */
function firstHeader(value: string | null): string | undefined {
  if (!value) return undefined;
  return value.split(",")[0]?.trim() || undefined;
}

/** Serializa los headers de la request a un objeto plano. */
function headersToObject(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  req.headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

/**
 * Backbone de captura del honeypot. Extrae telemetría de la request, clasifica
 * los payloads y persiste un evento en la tabla `events` de Supabase usando el
 * cliente service role.
 *
 * Está pensado para no romper nunca la respuesta del señuelo: si la inserción
 * falla, loguea el error y sigue. El honeypot debe responder de forma creíble
 * aunque el logging falle.
 */
export async function logEvent(req: Request, details: EventDetails): Promise<void> {
  try {
    const h = req.headers;

    const ip =
      firstHeader(h.get("x-forwarded-for")) ??
      h.get("x-real-ip") ??
      undefined;

    const attack_types: AttackType[] = classifyInput([
      details.username,
      details.password,
      details.path,
      typeof details.payload === "string"
        ? details.payload
        : details.payload
        ? JSON.stringify(details.payload)
        : undefined,
      ...(details.extraClassified ?? []),
    ]);

    const supabase = createAdminClient();
    const { error } = await supabase.from("events").insert({
      event_type: details.event_type,
      path: details.path ?? new URL(req.url).pathname,
      method: req.method,
      username: details.username ?? null,
      password: details.password ?? null,
      attack_types,
      ip: ip ?? null,
      // Headers de geolocalización que inyecta Vercel en el edge.
      country: h.get("x-vercel-ip-country") ?? null,
      city: h.get("x-vercel-ip-city") ?? null,
      asn: h.get("x-vercel-ip-asn") ?? null,
      user_agent: h.get("user-agent") ?? null,
      referer: h.get("referer") ?? null,
      accept_language: h.get("accept-language") ?? null,
      headers: headersToObject(req),
      fingerprint: details.fingerprint ?? null,
      timing_ms: details.timing_ms ?? null,
      payload: details.payload ?? null,
    });

    if (error) {
      console.error("[honeypot] fallo al insertar evento:", error.message);
    }
  } catch (err) {
    console.error("[honeypot] excepción en logEvent:", err);
  }
}
