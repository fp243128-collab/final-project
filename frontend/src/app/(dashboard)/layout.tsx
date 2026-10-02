"use client";

import { useEffect, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/layout/AppShell";
import { Loader2 } from "lucide-react";

function subscribe(callback: () => void) {
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

function getClientToken() {
  return localStorage.getItem("sentinelx_token");
}

function getServerToken() {
  return null;
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const token = useSyncExternalStore(subscribe, getClientToken, getServerToken);

  useEffect(() => {
    if (token === null || token === "") {
      router.replace("/login");
    }
  }, [token, router]);

  if (!token) {
    return (
      <div className="h-screen w-screen flex flex-col items-center justify-center bg-background text-foreground gap-3">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
        <p className="text-sm text-muted font-medium">Verifying SentinelX Session...</p>
      </div>
    );
  }

  return <AppShell>{children}</AppShell>;
}

