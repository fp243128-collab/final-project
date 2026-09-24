"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Bell, Search, User, LogOut } from "lucide-react";

export function Topbar() {
  const router = useRouter();
  const [userName, setUserName] = useState<string>("SecOps Analyst");

  useEffect(() => {
    try {
      const stored = localStorage.getItem("sentinelx_user");
      if (stored) {
        const u = JSON.parse(stored);
        if (u.name) setUserName(u.name);
      }
    } catch (e) {
      // Ignore
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("sentinelx_token");
    localStorage.removeItem("sentinelx_user");
    router.replace("/login");
  };

  return (
    <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-6 flex-shrink-0">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-64">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search assets, IPs..."
            className="w-full pl-9 pr-4 py-1.5 text-sm border-sentinel rounded-md bg-background focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
          />
        </div>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="text-xs font-mono text-muted bg-background border-sentinel px-2 py-1 rounded-md hidden md:block">
          Production-AWS-us-east-1
        </div>
        
        <button className="relative p-2 text-muted hover:text-foreground transition-colors" title="Notifications">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-critical rounded-full border border-surface"></span>
        </button>
        
        <div className="flex items-center gap-2 border-l border-border pl-4">
          <Link href="/settings" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
            <div className="w-8 h-8 rounded-full bg-primary/10 border-sentinel flex items-center justify-center text-primary font-medium text-sm">
              <User className="w-4 h-4" />
            </div>
            <span className="text-xs font-semibold text-foreground hidden sm:inline">{userName}</span>
          </Link>

          <button 
            onClick={handleLogout} 
            title="Sign out"
            className="p-1.5 text-muted hover:text-red-600 rounded-md hover:bg-red-50 transition-colors ml-1"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}

