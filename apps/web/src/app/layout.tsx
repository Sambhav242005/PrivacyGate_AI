import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PrivacyGate AI — Subscriber Insights",
  description: "Decrypt owner-authorized AI insights. Permitted fields only; raw telemetry never leaves the gateway.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="bg-mesh" aria-hidden />
        <main className="shell">{children}</main>
      </body>
    </html>
  );
}
