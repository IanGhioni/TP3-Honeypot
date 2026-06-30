-- ============================================================================
-- Honeypot — esquema de Supabase
-- Ejecutar en el SQL Editor del dashboard de Supabase.
-- ============================================================================

-- 1. Tabla única de eventos --------------------------------------------------
create table if not exists public.events (
  id              bigint generated always as identity primary key,
  created_at      timestamptz not null default now(),
  event_type      text not null,            -- login_attempt | scanner_hit | api_probe | file_bait
  path            text,
  method          text,
  username        text,                      -- solo login_attempt
  password        text,                      -- solo login_attempt
  attack_types    text[] not null default '{}',  -- sqli | xss | path_traversal | cmd_injection
  ip              text,
  country         text,
  city            text,
  asn             text,
  user_agent      text,
  referer         text,
  accept_language text,
  headers         jsonb,
  fingerprint     jsonb,
  timing_ms       integer,
  payload         jsonb
);

create index if not exists events_created_at_idx on public.events (created_at desc);
create index if not exists events_event_type_idx on public.events (event_type);
create index if not exists events_ip_idx on public.events (ip);

-- 2. RLS: activado y SIN políticas públicas ----------------------------------
-- La anon/publishable key no puede leer ni escribir esta tabla. El honeypot
-- inserta con la service_role key (que salta RLS), igual que el exporter al
-- leer vía la RPC de abajo (definida con security definer).
alter table public.events enable row level security;

-- 3. RPC de agregados para el exporter ---------------------------------------
-- Devuelve todas las métricas en un solo JSON (un round-trip por scrape).
create or replace function public.honeypot_metrics()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'by_type', coalesce((
      select jsonb_agg(jsonb_build_object('event_type', event_type, 'count', c))
      from (
        select event_type, count(*) as c
        from public.events
        group by event_type
      ) t
    ), '[]'::jsonb),

    'attack_types', coalesce((
      select jsonb_agg(jsonb_build_object('type', type, 'count', c))
      from (
        select unnest(attack_types) as type, count(*) as c
        from public.events
        where array_length(attack_types, 1) > 0
        group by type
      ) t
    ), '[]'::jsonb),

    'by_country', coalesce((
      select jsonb_agg(jsonb_build_object('country', country, 'count', c))
      from (
        select country, count(*) as c
        from public.events
        where country is not null
        group by country
      ) t
    ), '[]'::jsonb),

    'top_usernames', coalesce((
      select jsonb_agg(jsonb_build_object('username', username, 'count', c))
      from (
        select username, count(*) as c
        from public.events
        where username is not null and username <> ''
        group by username
        order by c desc
        limit 20
      ) t
    ), '[]'::jsonb),

    'top_passwords', coalesce((
      select jsonb_agg(jsonb_build_object('password', password, 'count', c))
      from (
        select password, count(*) as c
        from public.events
        where password is not null and password <> ''
        group by password
        order by c desc
        limit 20
      ) t
    ), '[]'::jsonb),

    'unique_ips', (select count(distinct ip) from public.events where ip is not null),

    'total_login_attempts', (select count(*) from public.events where event_type = 'login_attempt')
  );
$$;

-- La RPC se invoca con la service_role key desde el exporter; no se otorga a anon.
revoke all on function public.honeypot_metrics() from anon, authenticated;
