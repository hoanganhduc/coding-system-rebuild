#!/usr/bin/awk -f
# sanitize.awk -- ALLOWLIST sanitizer for untrusted OpenVPN configs (VPN Gate).
#
# A VPN Gate .ovpn comes from a public API and is run by our openvpn as root, so a
# malicious server could smuggle an --up / --tls-verify / --plugin / --setenv directive
# into the config and get code execution. A blocklist is bypassable: before reading a
# directive openvpn skips its whole isspace() class (space, tab, VT \013, FF \014, CR
# \015), then dequotes ("up") and unescapes (\up), so obfuscated hooks slip past a naive
# `^up ` grep. We therefore ALLOW only known-safe connectivity directives and inline PKI
# blocks and DROP everything else, so anything we do not recognize fails safe -- the
# tunnel just does not come up, it never runs attacker code.
#
# Method: for every line we reproduce openvpn's tokenizer to recover the real first token
# (the directive name) and keep the line only if that token is on the allowlist, re-emitted
# in a normalized form (tokens joined by single spaces) so no smuggled whitespace/quote/
# backslash survives into the output. Inline blocks (<ca>...</ca>) are matched
# case-sensitively (openvpn does not recognize <CA>); the body of an allowlisted PKI block
# is preserved byte-for-byte, and a non-allowlisted block is consumed and dropped whole. An
# unterminated block is a hard error (exit 3) so the caller discards the config.
#
# Exit: 0 = sanitized OK; 3 = unterminated inline block or ambiguous NUL input
# (fail closed).

BEGIN {
  # openvpn's isspace() class minus \n (our record separator): space, tab, VT, FF, CR.
  SP = sprintf(" \t%c%c%c", 11, 12, 13)
  NUL = sprintf("%c", 0)

  split("client dev dev-type proto remote resolv-retry nobind persist-key persist-tun " \
        "remote-cert-tls cipher data-ciphers data-ciphers-fallback auth key-direction " \
        "verb mute tun-mtu mssfix comp-lzo compress tls-version-min pull reneg-sec " \
        "keepalive ping ping-restart route-nopull auth-nocache", _d, " ")
  for (_i in _d) ALLOW_DIR[_d[_i]] = 1

  split("ca cert key dh tls-auth tls-crypt tls-crypt-v2 pkcs12 extra-certs", _b, " ")
  for (_i in _b) ALLOW_BLK[_b[_i]] = 1

  in_block = 0        # 0 = normal, 1 = inside a kept block, 2 = inside a dropped block
  close_tag = ""
  rejected = 0
}

# OpenVPN is a C parser, so an embedded NUL can terminate its view of a line
# before awk's view.  Reject the complete config instead of emitting an
# apparently normalized record with ambiguous trailing bytes.
index($0, NUL) > 0 {
  rejected = 1
  next
}

# --- inside a block: copy (kept) or drop the body verbatim until the matching close tag ---
in_block {
  s = $0
  # openvpn matches the close tag after skipping leading isspace, as a prefix (strncmp).
  while (length(s) > 0 && index(SP, substr(s, 1, 1)) > 0) s = substr(s, 2)
  if (substr(s, 1, length(close_tag)) == close_tag) {
    if (in_block == 1) print close_tag
    in_block = 0; close_tag = ""
    next
  }
  if (in_block == 1) print $0        # byte-for-byte body of a kept PKI block
  next
}

# --- normal state ---
{
  ntok = tokenize($0)
  if (ntok == 0) next                # blank line or comment: drop
  first = TOK[1]

  # inline block opener: openvpn treats a line with a single <tag> token as inline data.
  if (ntok == 1 && first ~ /^<[A-Za-z0-9_-]+>$/) {
    tag = substr(first, 2, length(first) - 2)
    close_tag = "</" tag ">"
    if (tag in ALLOW_BLK) { in_block = 1; print "<" tag ">" }
    else                    in_block = 2      # consume and drop the whole block
    next
  }

  if (first in ALLOW_DIR) {          # keep the directive, normalized
    out = TOK[1]
    for (i = 2; i <= ntok; i++) out = out " " TOK[i]
    print out
  }
  # everything else: drop
}

END {
  if (in_block || rejected) exit 3   # malformed input -> fail closed
}

# Tokenize a line the way openvpn's parse_line does: skip the isspace class, treat a
# leading ; or # as a comment, honor "..."/'...' quoting and backslash escaping (backslash
# escapes everywhere except inside single quotes). Fills the global TOK[1..n] and returns n.
function tokenize(s,   n, i, c, q, tok, cnt, k) {
  for (k in TOK) delete TOK[k]
  cnt = 0; n = length(s); i = 1
  while (i <= n) {
    while (i <= n && index(SP, substr(s, i, 1)) > 0) i++
    if (i > n) break
    c = substr(s, i, 1)
    if (c == ";" || c == "#") break                 # comment: end of line
    tok = ""
    if (c == "\"" || c == "'") {
      q = c; i++
      while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\\" && q == "\"") { i++; if (i <= n) { tok = tok substr(s, i, 1); i++ }; continue }
        if (c == q) { i++; break }
        tok = tok c; i++
      }
    } else {
      while (i <= n) {
        c = substr(s, i, 1)
        if (index(SP, c) > 0) break
        if (c == "\\") { i++; if (i <= n) { tok = tok substr(s, i, 1); i++ }; continue }
        tok = tok c; i++
      }
    }
    TOK[++cnt] = tok
  }
  return cnt
}
