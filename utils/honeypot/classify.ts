/**
 * Clasificador de payloads del honeypot.
 *
 * Aplica heurísticas (regex) sobre cualquier string de entrada (usuario,
 * contraseña, query string, body) y devuelve los tipos de ataque detectados.
 * No pretende ser un WAF: es para clasificar y graficar patrones de ataque en
 * el panel de métricas.
 */

export type AttackType =
  | "sqli"
  | "xss"
  | "path_traversal"
  | "cmd_injection";

const PATTERNS: Record<AttackType, RegExp[]> = {
  sqli: [
    /('|%27)\s*(or|and)\s*('|%27)?\s*\d+\s*=\s*\d+/i, // ' OR 1=1
    /\bunion\b\s+\bselect\b/i,
    /\b(select|insert|update|delete|drop|alter)\b\s+.*\b(from|into|table)\b/i,
    /(--|#|\/\*)/, // comentarios SQL
    /\bsleep\s*\(\s*\d+\s*\)/i, // SQLi basado en tiempo
    /\bor\b\s+\d+\s*=\s*\d+/i, // or 1=1 sin comillas
  ],
  xss: [
    /<\s*script\b/i,
    /<\s*\/\s*script\s*>/i,
    /on(error|load|click|mouseover)\s*=/i,
    /javascript\s*:/i,
    /<\s*(img|svg|iframe|body)\b[^>]*\bon\w+\s*=/i,
    /document\.(cookie|location)/i,
  ],
  path_traversal: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e(%2f|%5c)/i,
    /\/etc\/passwd\b/i,
    /(boot\.ini|win\.ini)\b/i,
  ],
  cmd_injection: [
    /[;&|]\s*(cat|ls|whoami|id|uname|curl|wget|nc|bash|sh|powershell|cmd)\b/i,
    /\$\([^)]*\)/, // $(...)
    /`[^`]*`/, // backticks
    /\|\s*\w+/, // pipe a comando
  ],
};

/**
 * Devuelve la lista (sin duplicados) de tipos de ataque detectados en los
 * strings provistos. Ignora valores vacíos/no-string.
 */
export function classifyInput(inputs: Array<string | undefined | null>): AttackType[] {
  const haystack = inputs
    .filter((v): v is string => typeof v === "string" && v.length > 0)
    .join("\n");

  if (!haystack) return [];

  const detected = new Set<AttackType>();
  for (const [type, regexes] of Object.entries(PATTERNS) as [
    AttackType,
    RegExp[]
  ][]) {
    if (regexes.some((re) => re.test(haystack))) {
      detected.add(type);
    }
  }
  return [...detected];
}
