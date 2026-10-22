import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "php2shell C2 - CVE-2026-109618/109619 Lab Console",
  description:
    "One-click exploit console and interactive shell for the php2shell CVE-2026-109618 / CVE-2026-109619 research lab (TryHackMe / local docker targets).",
  keywords: [
    "php2shell",
    "CVE-2026-109618",
    "CVE-2026-109619",
    "PHP",
    "security lab",
  ],
  authors: [{ name: "php2shell C2" }],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
