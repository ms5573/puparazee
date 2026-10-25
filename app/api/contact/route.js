import crypto from "node:crypto";
import { NextResponse } from "next/server";
import { submitLead } from "../../../lib/contact";
import { createRateLimiter } from "../../../lib/rate-limit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const perIp = createRateLimiter({ limit: 5, windowMs: 60 * 60 * 1000 });

function clientIp(request) {
  const real = request.headers.get("x-real-ip");
  if (real) return real.trim().slice(0, 80);
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim().slice(0, 80);
  return null;
}

export function GET(request) {
  const token = crypto.randomBytes(16).toString("hex");
  const response = NextResponse.json({ csrf: token });
  const forwarded = request.headers.get("x-forwarded-proto");
  const secure = forwarded
    ? forwarded.split(",")[0].trim() === "https"
    : request.nextUrl.protocol === "https:";
  response.cookies.set("lead_csrf", token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure,
    maxAge: 60 * 60 * 2,
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export async function POST(request) {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (origin) {
    try {
      if (new URL(origin).host !== host) {
        return Response.json({ error: "Submission rejected." }, { status: 403, headers: { "Cache-Control": "no-store" } });
      }
    } catch {
      return Response.json({ error: "Submission rejected." }, { status: 403, headers: { "Cache-Control": "no-store" } });
    }
  }

  let payload = {};
  try {
    const text = await request.text();
    if (text.length > 20000) {
      return Response.json({ error: "Please shorten the message." }, { status: 400, headers: { "Cache-Control": "no-store" } });
    }
    payload = text ? JSON.parse(text) : {};
  } catch {
    return Response.json({ error: "Please submit the form again." }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const result = await submitLead(
    {
      ...payload,
      cookie: request.cookies.get("lead_csrf")?.value || "",
      ip: clientIp(request),
      ua: request.headers.get("user-agent") || "",
    },
    {
      env: process.env,
      rateLimit: (ip, now) => perIp.allow(ip || "unknown", now),
    },
  );

  return Response.json(result.body, { status: result.status, headers: { "Cache-Control": "no-store" } });
}
