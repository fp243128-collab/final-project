import Link from "next/link";
import {
  ShieldAlert,
  Activity,
  Server,
  AlertTriangle,
  Bell,
  BarChart2,
  Terminal,
  FileText,
  Settings,
  Shield,
  FileSearch,
  LogOut
} from "lucide-react";

export function Sidebar() {
  return (
    <aside className="w-64 bg-sidebar text-sidebar-foreground flex flex-col h-full border-r border-border flex-shrink-0">
      <div className="h-14 flex items-center px-4 font-bold text-lg border-b border-border/10 tracking-tight gap-2">
        <Shield className="w-5 h-5 text-primary" />
        SENTINELX
      </div>

      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-6">
        <div>
          <div className="text-xs font-semibold text-sidebar-foreground/50 uppercase tracking-wider mb-2 px-3">
            Overview
          </div>
          <div className="space-y-1">
            <NavItem href="/overview" icon={<Activity />} label="Security Overview" />
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold text-sidebar-foreground/50 uppercase tracking-wider mb-2 px-3">
            Security
          </div>
          <div className="space-y-1">
            <NavItem href="/threats" icon={<ShieldAlert />} label="Threat Detection" />
            <NavItem href="/alerts" icon={<Bell />} label="Alert Center" />
            <NavItem href="/risk" icon={<AlertTriangle />} label="Risk Center" />
            <NavItem href="/analytics" icon={<BarChart2 />} label="Analytics" />
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold text-sidebar-foreground/50 uppercase tracking-wider mb-2 px-3">
            Cloud Security
          </div>
          <div className="space-y-1">
            <NavItem href="/cspm" icon={<FileSearch />} label="CSPM" />
            <NavItem href="/resources" icon={<Server />} label="Cloud Resources" />
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold text-sidebar-foreground/50 uppercase tracking-wider mb-2 px-3">
            Operations
          </div>
          <div className="space-y-1">
            <NavItem href="/monitoring" icon={<Activity />} label="Monitoring" />
            <NavItem href="/devsecops" icon={<Terminal />} label="DevSecOps" />
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold text-sidebar-foreground/50 uppercase tracking-wider mb-2 px-3">
            Intelligence
          </div>
          <div className="space-y-1">
            <NavItem href="/assistant" icon={<Terminal />} label="AI Assistant" />
            <NavItem href="/reports" icon={<FileText />} label="Reports" />
          </div>
        </div>

        <div>
          <div className="text-xs font-semibold text-sidebar-foreground/50 uppercase tracking-wider mb-2 px-3">
            Administration
          </div>
          <div className="space-y-1">
            <NavItem href="/audit-logs" icon={<FileText />} label="Audit Logs" />
            <NavItem href="/settings" icon={<Settings />} label="Settings" />
          </div>
        </div>

        <div className="pt-6 border-t border-border/10">
          <div className="space-y-1">
            <NavItem href="/login" icon={<LogOut className="text-red-500" />} label="Sign Out" />
          </div>
        </div>
      </nav>
    </aside>
  );
}

function NavItem({ href, icon, label }: { href: string; icon: React.ReactNode; label: string }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium hover:bg-sidebar-foreground/10 transition-colors"
    >
      <div className="w-4 h-4 flex items-center justify-center [&>svg]:w-4 [&>svg]:h-4">
        {icon}
      </div>
      {label}
    </Link>
  );
}
