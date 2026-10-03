"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/layout/AppShell";
import { Loader2 } from "lucide-react";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    const checkAuth = () => {
      const token = localStorage.getItem("sentinelx_token");
      if (!token) {
        setIsAuthenticated(false);
        router.replace("/login");
      } else {
        setIsAuthenticated(true);
      }
    };

    checkAuth();
    window.addEventListener("storage", checkAuth);
    return () => window.removeEventListener("storage", checkAuth);
  }, [router]);

  if (isAuthenticated === null || !isAuthenticated) {
    return (
      <div className="h-screen w-screen flex flex-col items-center justify-center bg-background text-foreground gap-3">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
        <p className="text-sm text-muted font-medium">Verifying SentinelX Session...</p>
      </div>
    );
  }

  return <AppShell>{children}</AppShell>;
}

