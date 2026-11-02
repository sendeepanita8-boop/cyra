import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
  weight: ["400", "500", "600", "700", "800", "900"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://cyra.app"),
  title: {
    default: "CYRA — Website Security Intelligence",
    template: "%s | CYRA Security",
  },
  description:
    "Instantly audit any website's security posture. CYRA inspects HTTPS/TLS configuration, HTTP security headers, DNS health, cookies, and exposure indicators to generate a professional security report.",
  keywords: [
    "website security scanner",
    "security headers checker",
    "TLS certificate checker",
    "DNS security audit",
    "OWASP security headers",
    "CSP checker",
    "HSTS checker",
    "website vulnerability scanner",
    "security posture assessment",
    "CYRA security",
  ],
  authors: [{ name: "CYRA Security Intelligence" }],
  creator: "CYRA Security Intelligence",
  publisher: "CYRA Security Intelligence",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://cyra.app",
    siteName: "CYRA Security Intelligence",
    title: "CYRA — Website Security Intelligence",
    description:
      "Instantly audit any website's security posture. Inspect HTTPS, headers, DNS, cookies, and exposure indicators.",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "CYRA — Website Security Intelligence",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "CYRA — Website Security Intelligence",
    description:
      "Free instant security audit for any website. TLS, headers, DNS, cookies, exposure analysis.",
    images: ["/og-image.png"],
    creator: "@cyrasecurity",
  },
  icons: {
    icon: "/favicon.ico",
    shortcut: "/favicon.ico",
    apple: "/apple-touch-icon.png",
  },
  manifest: "/site.webmanifest",
  alternates: {
    canonical: "https://cyra.app",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable} data-scroll-behavior="smooth">
      <head>
        <meta name="theme-color" content="#f8fafc" />
        <meta name="color-scheme" content="light" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}