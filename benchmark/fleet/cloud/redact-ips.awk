# awk -v keep="<ip> <ip> ..." -f redact-ips.awk: every IPv4 address in the input except the kept ones (the soak
# droplets), 0.0.0.0 and 127.x becomes <operator>. soak.sh collect runs the collector journal through it, so the
# operator workstation's public address (its /api/health and /api/fleet reads) never reaches the repo.
BEGIN { n = split(keep, k, " "); for (i = 1; i <= n; i++) ok[k[i]] = 1; ok["0.0.0.0"] = 1 }
{
  out = ""; s = $0
  while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
    a = substr(s, RSTART, RLENGTH)
    out = out substr(s, 1, RSTART - 1) ((a in ok || a ~ /^127\./) ? a : "<operator>")
    s = substr(s, RSTART + RLENGTH)
  }
  print out s
}
