import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/*
 * Intercepta las rutas que típicamente escanean bots y herramientas
 * automáticas, y las reescribe a /api/trap. NO escribe en la base acá: el
 * proxy no es para fetching/DB (el caching de fetch no aplica). Solo reenvía
 * la ruta original en un header para que el route handler haga el logging y
 * responda algo creíble.
 */
export function proxy(request: NextRequest) {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-trap-path", request.nextUrl.pathname);

  return NextResponse.rewrite(new URL("/api/trap", request.url), {
    request: { headers: requestHeaders },
  });
}

export const config = {
  matcher: [
    "/admin",
    "/admin/:path*",
    "/wp-admin/:path*",
    "/wp-login.php",
    "/administrator/:path*",
    "/phpmyadmin/:path*",
    "/.env",
    "/.git/:path*",
    "/backup.zip",
    "/config.php",
    "/.aws/:path*",
  ],
};
