Monitor Cloudflare traffic and auto-block abusive IPs.
 
How it works
  1. Every POLL_INTERVAL seconds, pulls per-IP traffic stats for the last
     WINDOW_MINUTES from Cloudflare's GraphQL Analytics API.
  2. Scores each IP using simple heuristics (request volume, error ratio,
     probing of sensitive paths, login hammering).
  3. IPs over the threshold get a "block" IP Access Rule on your zone.
  4. Blocks expire automatically after BLOCK_HOURS (rules are deleted).
