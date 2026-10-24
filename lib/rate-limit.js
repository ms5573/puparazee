"use strict";

function createRateLimiter({ limit, windowMs }) {
  const hits = new Map();
  function allow(key, now = Date.now()) {
    const recent = (hits.get(key) || []).filter((stamp) => now - stamp < windowMs);
    if (recent.length >= limit) {
      hits.set(key, recent);
      return false;
    }
    recent.push(now);
    hits.set(key, recent);
    return true;
  }
  function reset() {
    hits.clear();
  }
  return { allow, reset };
}

module.exports = { createRateLimiter };
