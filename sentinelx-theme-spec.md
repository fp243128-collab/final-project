# SentinelX — Visual Direction & Theme Policy (Enforced)

## 1. Visual Direction & Principles

**Authentic Enterprise SaaS.** Crisp, clean, trustworthy, high-density data tables and clear operational panels — think Cloudflare Dashboard, AWS Security Hub, Microsoft Defender, Datadog. Not a hacker terminal, not a sci-fi HUD.

**Theme policy — READ BEFORE BUILDING ANYTHING:**
> The default and ONLY theme for this build is **Light Enterprise SaaS**. There is no dark mode in v1. Any component, page, or screen generated with a dark/black background is a defect and must be rejected in review, not shipped and "fixed later."

**Required palette (exact hex — do not substitute or "improve"):**

| Role | Hex | Notes |
| --- | --- | --- |
| Page background | `#FFFFFF` | Pure white |
| Card/container surface | `#FFFFFF` | Pure white — separated from page by the 1px border, not a shade difference |
| Borders/dividers | `#E2E8F0` | Slate 200, 1px solid only |
| Primary text | `#0F172A` | Slate 900 |
| Secondary/muted text | `#64748B` | Slate 500 |
| Accent/primary action | `#2563EB` | Royal blue |
| Sidebar | `#0F172A` OR `#FFFFFF` | Navy sidebar with white content is acceptable; navy background elsewhere is NOT |
| Success | `#16A34A` | |
| Warning | `#D97706` | |
| Critical | `#DC2626` | |
| Info | `#0284C7` | |

**Explicitly forbidden — reject on sight:**

- Any `background`, `background-color`, or CSS variable resolving to a hex darker than `#1E293B` outside the sidebar/topbar
- `prefers-color-scheme: dark` media queries or any dark-mode toggle/logic in v1
- Neon borders, glowing `box-shadow` (anything with blur > 8px and saturated color), or `filter: drop-shadow` used decoratively
- Gradients of any kind on backgrounds or cards (flat fills only)
- Any color not in the table above, including "close enough" substitutes an agent might generate (e.g. `#111827`, `#1A1A2E`, `#0D1117`)
- Glassmorphism, backdrop-blur, translucent panels

**Allowed shadow (the only one):**

```css
box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
```

**Density & typography.** High information density, compact tables, tabular figures (`font-mono` / JetBrains Mono or SF Mono) for IPs, ports, hashes, timestamps, rule IDs. UI font: Inter or system stack. No display/decorative fonts.

**Enforcement note for the build agent:** Before generating or modifying any component, check its background and shadow values against this table. If a value isn't in the table, don't invent one — ask or default to `#FFFFFF` / `#F8FAFC`. This rule takes precedence over general "make it look like a security dashboard" instincts.

---

## 2. Layout & Information Architecture

- **Left Navigation**: white with slate borders, clear section headers, standard 16px icons.
- **Topbar**: 56px height, breadcrumb path, global asset/IP search, notification tray, tenant/environment switcher (`Production-AWS-us-east-1`), user profile.
- **Data Display**: Structured standard tables with sticky headers, clear zebra or clean line hover states, inline badges, and filter bars.
