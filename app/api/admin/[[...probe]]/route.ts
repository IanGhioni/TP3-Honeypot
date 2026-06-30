import { logEvent } from "@/utils/honeypot/capture";

/**
 * API señuelo. Catch-all opcional que cubre /api/admin y cualquier subruta
 * jugosa (/api/admin/users, /api/admin/keys, /api/admin/export, …). Registra
 * el sondeo con el body/query crudos (el clasificador detecta inyecciones acá
 * también) y devuelve JSON fake plausible. No expone nada real.
 */

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const query = Object.fromEntries(url.searchParams.entries());

  let body: string | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") {
    try {
      body = await request.text();
    } catch {
      // sin body legible
    }
  }

  await logEvent(request, {
    event_type: "api_probe",
    path: url.pathname,
    payload: { query, body },
    extraClassified: [url.pathname, body, JSON.stringify(query)],
  });

  // Respuesta fake plausible para mantener el interés del atacante.
  return Response.json(
    {
      status: "ok",
      data: [],
      meta: { page: 1, per_page: 50, total: 0 },
    },
    { status: 200 }
  );
}

export async function GET(request: Request) {
  return handle(request);
}

export async function POST(request: Request) {
  return handle(request);
}

export async function PUT(request: Request) {
  return handle(request);
}

export async function DELETE(request: Request) {
  return handle(request);
}
