import { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // Don't index scan results or API
        disallow: ["/api/", "/_next/"],
      },
    ],
    sitemap: "https://cyra.app/sitemap.xml",
    host: "https://cyra.app",
  };
}
