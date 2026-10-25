import { checkSite } from "../../../lib/check-site";
import { createRateLimiter } from "../../../lib/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 25;
export const dynamic = "force-dynamic";

const perIp = createRateLimiter({ limit: 20, windowMs: 60 * 60 * 1000 });

function clientIp(request) {
  const real = request.headers.get("x-real-ip");
  if (real) return real.trim().slice(0, 80);
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim().slice(0, 80);
  return "unknown";
}

export async function POST(request) {
  if (!perIp.allow(clientIp(request))) {
    return Response.json(
      { verdict: "rate_limited", message: "Too many checks this hour." },
      { status: 429, headers: { "Cache-Control": "no-store" } },
    );
  }

  let payload = {};
  try {
    const text = await request.text();
    if (text.length > 8192) {
      return Response.json(
        { verdict: "invalid", message: "Not a valid public website URL. Enter a domain like example.com." },
        { status: 400, headers: { "Cache-Control": "no-store" } },
      );
    }
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = {};
  }

  try {
    const result = await checkSite(typeof payload.url === "string" ? payload.url : "");
    return Response.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json(
      { verdict: "unreachable", message: "Could not reach that site: connection failed" },
      { status: 502, headers: { "Cache-Control": "no-store" } },
    );
  }
}
