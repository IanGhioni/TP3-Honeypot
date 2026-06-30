"use client";

import { useEffect, useRef, useState } from "react";

import { buildFingerprint } from "@/utils/honeypot/fingerprint";

/*
 * Login falso del honeypot. Nunca autentica: siempre devuelve "credenciales
 * inválidas" para inducir reintentos (credential stuffing). En cada submit
 * envía credenciales + fingerprint + tiempo en página a /api/login.
 */

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const mountedAt = useRef(0);

  useEffect(() => {
    mountedAt.current = Date.now();
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          fingerprint: buildFingerprint(),
          timing_ms: Date.now() - mountedAt.current,
        }),
      });
    } catch {
      // ignorar errores de red: igual mostramos el error genérico
    }

    // Pequeña demora para parecer un login real.
    setTimeout(() => {
      setLoading(false);
      setPassword("");
      setError("Usuario o contraseña incorrectos. Intentá nuevamente.");
    }, 900);
  }

  return (
    <div className="relative flex min-h-full flex-1 items-center justify-center bg-[#14171A] px-4 py-12 font-sans text-[#E7EAEE]">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(120% 80% at 50% 112%, rgba(125,160,192,0.10), transparent 58%)",
        }}
      />

      <div className="relative w-full max-w-[400px]">
        {/* marca */}
        <div className="mb-9">
          <div className="flex items-center gap-2.5">
            <svg viewBox="0 0 24 24" className="h-6 w-6" aria-hidden>
              <path d="M7 2v11h3v9l7-12h-4l4-8z" fill="#F5C542" />
            </svg>
            <span className="font-display text-xl font-semibold tracking-tight">
              Deuterio S.A.
            </span>
          </div>
          <p className="mt-1.5 text-xs text-[#8C95A0]">Portal Corporativo</p>
        </div>

        <h1 className="font-display text-[28px] font-semibold leading-tight tracking-tight">
          Iniciá sesión
        </h1>
        <p className="mt-2 text-sm text-[#9AA3AD]">
          Ingresá con tu usuario corporativo.
        </p>

        <form onSubmit={handleSubmit} className="mt-8 flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <label htmlFor="username" className="text-sm text-[#B4BCC6]">
              Usuario
            </label>
            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="rounded-lg border border-[#272C32] bg-[#0F1215] px-3.5 py-2.5 text-sm text-[#E7EAEE] outline-none transition-colors placeholder:text-[#5E6770] focus:border-[#6B8AA8] focus:ring-2 focus:ring-[#6B8AA8]/25"
            />
          </div>

          <div className="flex flex-col gap-2">
            <label htmlFor="password" className="text-sm text-[#B4BCC6]">
              Contraseña
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-lg border border-[#272C32] bg-[#0F1215] px-3.5 py-2.5 text-sm text-[#E7EAEE] outline-none transition-colors placeholder:text-[#5E6770] focus:border-[#6B8AA8] focus:ring-2 focus:ring-[#6B8AA8]/25"
            />
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-lg border border-[#5E3231] bg-[#211517] px-3.5 py-2.5 text-sm text-[#D9A2A0]"
            >
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="mt-2 rounded-lg bg-[#D7DEE6] px-4 py-2.5 text-sm font-semibold text-[#14171A] outline-none transition-colors hover:bg-[#E8EDF2] focus-visible:ring-2 focus-visible:ring-[#8FA8C2]/50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Ingresando…" : "Ingresar"}
          </button>
        </form>

        <a
          href="/admin"
          className="mt-5 inline-block text-sm text-[#9AA3AD] underline-offset-4 transition-colors hover:text-[#8FA8C2] hover:underline"
        >
          ¿Olvidaste tu contraseña?
        </a>

        <div className="mt-10 border-t border-[#20242A] pt-5 text-xs text-[#6B7480]">
          Deuterio S.A. · Mesa de Ayuda interno 4357
        </div>
      </div>
    </div>
  );
}
