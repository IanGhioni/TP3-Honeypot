import type { MetadataRoute } from "next";

/**
 * robots.txt del honeypot. Los `Disallow` apuntan a rutas "secretas" jugosas:
 * los scanners y atacantes suelen leer robots.txt y van directo a lo prohibido,
 * cayendo en las rutas-trampa que intercepta el proxy.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      disallow: [
        "/admin",
        "/wp-admin",
        "/phpmyadmin",
        "/backup.zip",
        "/.env",
        "/.git",
        "/config.php",
        "/api/admin",
      ],
    },
  };
}
