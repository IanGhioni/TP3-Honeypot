import { logEvent, type EventType } from "@/utils/honeypot/capture";

/**
 * Endpoint interno al que el proxy reescribe las rutas-trampa. Registra el hit
 * y devuelve una respuesta creíble según la ruta original (header x-trap-path),
 * incluyendo tokens *canary* únicos: si alguna vez aparecen usados en otro lado,
 * sabemos que salieron de este honeypot.
 */

/** Rutas que simulan archivos sensibles expuestos. */
function isFileBait(path: string): boolean {
  return /\.(env|zip|php)$|\/\.git|\/\.aws/i.test(path);
}

/** Genera un token canary único por respuesta. */
function canary(): string {
  return `canary_${crypto.randomUUID().replace(/-/g, "")}`;
}

/** Cuerpo + content-type creíbles según la ruta solicitada. */
function fakeResponse(path: string): {
  body: string;
  contentType: string;
  status: number;
} {
  if (/\.env$/i.test(path)) {
    return {
      contentType: "text/plain; charset=utf-8",
      status: 200,
      body: [
        "APP_ENV=production",
        "APP_DEBUG=false",
        `APP_KEY=base64:${canary()}`,
        "DB_CONNECTION=mysql",
        "DB_HOST=10.0.0.12",
        "DB_DATABASE=corp_main",
        "DB_USERNAME=admin",
        `DB_PASSWORD=${canary()}`,
        `AWS_ACCESS_KEY_ID=AKIA${canary().slice(0, 16).toUpperCase()}`,
        `AWS_SECRET_ACCESS_KEY=${canary()}`,
      ].join("\n"),
    };
  }

  if (/\/\.git/i.test(path)) {
    return {
      contentType: "text/plain; charset=utf-8",
      status: 200,
      body: [
        "[core]",
        "\trepositoryformatversion = 0",
        "\tfilemode = false",
        "[remote \"origin\"]",
        `\turl = https://git.corp.internal/main.git`,
        `\t# token: ${canary()}`,
      ].join("\n"),
    };
  }

  if (/\/\.aws/i.test(path)) {
    return {
      contentType: "text/plain; charset=utf-8",
      status: 200,
      body: [
        "[default]",
        `aws_access_key_id = AKIA${canary().slice(0, 16).toUpperCase()}`,
        `aws_secret_access_key = ${canary()}`,
      ].join("\n"),
    };
  }

  if (/\.zip$/i.test(path) || /\.php$/i.test(path)) {
    return {
      contentType: "text/plain; charset=utf-8",
      status: 200,
      body: `# backup index\n# generated nightly\n# ref: ${canary()}\n`,
    };
  }

  // Paneles admin (wp-admin, administrator, phpmyadmin, wp-login.php).
  return {
    contentType: "text/html; charset=utf-8",
    status: 200,
    body: `<!doctype html><html><head><title>Admin Login</title></head>
<body style="font-family:sans-serif;max-width:320px;margin:80px auto">
<h2>Administrator Login</h2>
<form method="post">
<p><input name="user" placeholder="Username" style="width:100%"></p>
<p><input name="pwd" type="password" placeholder="Password" style="width:100%"></p>
<p><button type="submit">Log In</button></p>
</form>
<!-- session: ${canary()} -->
</body></html>`,
  };
}

async function handle(request: Request): Promise<Response> {
  const path = request.headers.get("x-trap-path") ?? new URL(request.url).pathname;

  // Capturar query y body crudos para clasificar y guardar.
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

  const event_type: EventType = isFileBait(path) ? "file_bait" : "scanner_hit";

  await logEvent(request, {
    event_type,
    path,
    payload: { query, body },
    extraClassified: [path, body, JSON.stringify(query)],
  });

  const fake = fakeResponse(path);
  return new Response(fake.body, {
    status: fake.status,
    headers: { "content-type": fake.contentType },
  });
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

export async function HEAD(request: Request) {
  return handle(request);
}
