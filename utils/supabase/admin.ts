import { createClient } from "@supabase/supabase-js";

/**
 * Cliente Supabase con service role. SOLO debe usarse en código de servidor
 * (route handlers / server actions). Salta RLS, por lo que la tabla `events`
 * puede tener RLS activado sin políticas públicas: nadie la lee/escribe con la
 * anon key, pero el honeypot sí puede insertar eventos.
 *
 * NUNCA importar este módulo desde un componente cliente ni exponer la key en
 * variables NEXT_PUBLIC_*.
 */
export function createAdminClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !serviceRoleKey) {
    throw new Error(
      "Faltan NEXT_PUBLIC_SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en el entorno."
    );
  }

  return createClient(url, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}
