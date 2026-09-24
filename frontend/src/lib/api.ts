const rawApiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").trim().replace(/\/+$/, "");

// If deployed on railway or modern web with https, upgrade http to https to prevent mixed content blocking
export const API_URL = (
  typeof window !== "undefined" && window.location.protocol === "https:" && rawApiUrl.startsWith("http://") && !rawApiUrl.includes("localhost")
    ? rawApiUrl.replace("http://", "https://")
    : rawApiUrl
);

export const WS_URL = process.env.NEXT_PUBLIC_WS_URL || (
  API_URL.startsWith("https://") 
    ? API_URL.replace("https://", "wss://") + "/ws/live"
    : API_URL.replace("http://", "ws://") + "/ws/live"
);

