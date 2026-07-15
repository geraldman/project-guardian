import type { Metadata } from "next";
import "./globals.css";
import "./print.css";

// System font stack only — next/font/google downloads at build time, which
// breaks the offline Docker build.

export const metadata: Metadata = {
  title: "Guardian Pulse",
  description: "Single-pane security HUD for the GUARDIAN monitoring stack",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
