import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import "./print.css";

// Vendored JetBrains Mono via next/font/local (OFL, files in app/fonts/) —
// next/font/google downloads at build time, which breaks the offline Docker
// build; local files keep the build hermetic AND give the HUD a face that
// isn't whatever the host OS ships.
const jetbrains = localFont({
  src: [
    { path: "./fonts/JetBrainsMono-Regular.woff2", weight: "400", style: "normal" },
    { path: "./fonts/JetBrainsMono-Medium.woff2", weight: "500", style: "normal" },
    { path: "./fonts/JetBrainsMono-Bold.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-jb",
  display: "swap",
});

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
    <html lang="en" className={jetbrains.variable}>
      <body>{children}</body>
    </html>
  );
}
