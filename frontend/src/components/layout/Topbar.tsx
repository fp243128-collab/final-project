import Link from "next/link";
import { Bell, Search, User } from "lucide-react";

export function Topbar() {
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
        <div className="text-xs font-mono text-muted bg-background border-sentinel px-2 py-1 rounded-md">
          Production-AWS-us-east-1
        </div>
        
        <button className="relative p-2 text-muted hover:text-foreground transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-critical rounded-full border border-surface"></span>
        </button>
        
        <Link href="/settings" className="w-8 h-8 rounded-full bg-primary/10 hover:bg-primary/20 border-sentinel flex items-center justify-center text-primary font-medium text-sm transition-colors cursor-pointer">
          <User className="w-4 h-4" />
        </Link>
      </div>
    </header>
  );
}
