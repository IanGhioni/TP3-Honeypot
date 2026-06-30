import { logEvent } from "@/utils/honeypot/capture";
import type { Fingerprint } from "@/utils/honeypot/fingerprint";

/**
 * Recibe el submit del login falso. Registra el intento y SIEMPRE responde
 * "credenciales inválidas". Nunca autentica ni consulta usuarios reales.
 */
export async function POST(request: Request) {
  let body: {
    username?: string;
    password?: string;
    fingerprint?: unknown;
    timing_ms?: number;
  } = {};

  try {
    body = await request.json();
  } catch {
    // body inválido: igual lo registramos como intento
  }

  await logEvent(request, {
    event_type: "login_attempt",
    path: "/",
    username: body.username,
    password: body.password,
    // Dato no confiable del cliente: se guarda tal cual como jsonb.
    fingerprint: body.fingerprint as Fingerprint | undefined,
    timing_ms: typeof body.timing_ms === "number" ? body.timing_ms : undefined,
  });

  return Response.json(
    { ok: false, error: "invalid_credentials" },
    { status: 401 }
  );
}
