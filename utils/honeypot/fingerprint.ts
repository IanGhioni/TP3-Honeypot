/**
 * Fingerprint básico del browser para el señuelo de login.
 *
 * Es best-effort y corre en el cliente: todos los campos son opcionales y
 * cualquier fallo (navegadores que bloquean el canvas, APIs ausentes) se ignora
 * para no romper el envío del intento de login.
 */

export interface Fingerprint {
  screen: string;
  viewport: string;
  timezone: string;
  language: string;
  platform: string;
  hardwareConcurrency: number;
  canvas?: string;
}

/** Hash corto del canvas. Devuelve undefined si el navegador lo bloquea. */
function canvasHash(): string | undefined {
  try {
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    if (!ctx) return undefined;
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillText("honeypot-fp", 2, 2);
    return c.toDataURL().slice(-32);
  } catch {
    return undefined;
  }
}

/** Recolecta el fingerprint del browser. Sólo usar en el cliente. */
export function buildFingerprint(): Fingerprint {
  return {
    screen: `${window.screen.width}x${window.screen.height}`,
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency,
    canvas: canvasHash(),
  };
}
