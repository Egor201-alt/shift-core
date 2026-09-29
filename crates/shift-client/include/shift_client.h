#ifndef SHIFT_CLIENT_H
#define SHIFT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * config_json fields:
 *   server_addr        "host:port" of the shift-server           (required)
 *   server_public_key  64 hex chars, the server's X25519 key      (required)
 *   psk_passphrase      OR psk_hex (exactly one required)
 *   cipher              "auto" | "chacha20poly1305" | "aes256gcm" (default "auto")
 *   socks_bind          "host:port" for the local SOCKS5 server   (default "127.0.0.1:1080")
 *   connect_timeout_ms                                            (default 5000)
*   camouflage_sni       real hostname for a decoy TLS ClientHello (default: none)
 *
 * Returns a positive handle on success, or a negative value on failure.
 */
long long shift_client_start(const char *config_json);

/* Stops and tears down the client identified by handle. 0 on success. */
int shift_client_stop(long long handle);

/* Frees a string previously returned by a shift-client function that
 * documents ownership transfer. Safe to call with NULL. */
void shift_client_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* SHIFT_CLIENT_H */
