import "./globals.css";

export const metadata = {
  metadataBase: new URL("https://puparazee.com"),
  title: "PHP2Shell checker",
  description:
    "Free passive PHP2Shell checker for CVE-2026-109618 and CVE-2026-109619. Compares the PHP version your server already advertises with the fixed releases. Not an exploit test.",
  alternates: { canonical: "/" },
  openGraph: {
    title: "PHP2Shell checker",
    description: "Is your site affected by PHP2Shell? A free passive check of the version headers your server already sends.",
    url: "https://puparazee.com/",
    siteName: "PHP2Shell checker",
    type: "website",
  },
  twitter: { card: "summary" },
  robots: { index: true, follow: true },
};

export const viewport = {
  themeColor: "#070a0e",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
