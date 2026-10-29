// Hand-written interface for libwgproxy.a (built from Vendor/wgproxy-src by
// scripts/build-wgproxy.sh). cgo's generated header pulls in Go types Swift
// doesn't need, so only the exported C functions are declared here.
#ifndef WGPROXY_H
#define WGPROXY_H

/// Starts (or restarts) the tunnel + loopback HTTP proxy from a JSON config.
/// Returns NULL on success, otherwise an error string to free with LocusWGFree.
char *LocusWGStart(const char *config_json);

/// Replaces the WireGuard peer (server) without restarting the proxy.
char *LocusWGSetPeer(const char *peer_json);

void LocusWGStop(void);

/// JSON status: running, last_handshake (unix seconds), rx_bytes, tx_bytes.
/// Always non-NULL; free with LocusWGFree.
char *LocusWGStatus(void);

void LocusWGFree(char *p);

#endif
