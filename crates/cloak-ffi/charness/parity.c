/* Minimal C parity harness for cloak-ffi (E7 done-when).
 *
 * Runs the full cloak-core vector corpus through the C ABI — one-shot
 * and streamed — and asserts byte-for-byte equality with the expected
 * outputs, plus the lifecycle/error paths a C caller depends on. This
 * is the proof that E7's parity claim stands on its own, without the
 * cloak-go suite (which exercises the same library through cgo).
 *
 * Usage:
 *   cargo build -p cloak-ffi --release
 *   cargo run --example export-vectors -p cloak-core > /tmp/vectors.json
 *   cc -std=c99 -Wall -Wextra -Werror -Icrates/cloak-ffi/include \
 *      crates/cloak-ffi/charness/parity.c \
 *      target/release/libcloak_ffi.a -lm -ldl -lpthread \
 *      -o /tmp/cloak-charness            # (linux; no extra libs on macOS)
 *   CLOAK_DIGEST_KEY=integration-test-key /tmp/cloak-charness /tmp/vectors.json
 *
 * The "JSON parser" below is deliberately not one: the fixture is ours,
 * machine-generated and flat — an array of objects whose consumed
 * fields are "name" and two hex strings ("input"/"expected"). Hex never
 * contains the key tokens (n, m, p … are not hex digits), values never
 * contain braces or escapes, so slicing on '{'…'}' and scanning for the
 * quoted keys inside each object is exact — and independent of the
 * serializer's key order (serde_json sorts keys alphabetically).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cloak.h>

static const char *CONFIG =
    "[redaction]\n"
    "digest_key = \"env:CLOAK_DIGEST_KEY\"\n";

static void die(const char *vector, const char *what) {
    fprintf(stderr, "FAIL [%s]: %s\n", vector, what);
    exit(1);
}

static void die_err(const char *vector, const char *what, struct CloakBuf err) {
    fprintf(stderr, "FAIL [%s]: %s: %.*s\n", vector, what, (int)err.len,
            err.ptr ? (const char *)err.ptr : "");
    cloak_buf_free(err);
    exit(1);
}

/* Read a whole file into a NUL-terminated heap buffer. */
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die(path, "cannot open vectors file");
    if (fseek(f, 0, SEEK_END) != 0) die(path, "seek failed");
    long size = ftell(f);
    if (size < 0) die(path, "tell failed");
    rewind(f);
    char *buf = malloc((size_t)size + 1);
    if (!buf) die(path, "out of memory");
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) die(path, "short read");
    buf[size] = '\0';
    fclose(f);
    return buf;
}

/* After a `"key"` token: skip to ':', then read the quoted value.
 * Returns a malloc'd copy and advances *pp past the closing quote. */
static char *read_quoted_value(const char **pp) {
    const char *p = strchr(*pp, ':');
    if (!p) die("parser", "missing ':' after key");
    p = strchr(p, '"');
    if (!p) die("parser", "missing opening quote");
    p++;
    const char *end = strchr(p, '"');
    if (!end) die("parser", "missing closing quote");
    size_t len = (size_t)(end - p);
    char *out = malloc(len + 1);
    if (!out) die("parser", "out of memory");
    memcpy(out, p, len);
    out[len] = '\0';
    *pp = end + 1;
    return out;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    die("parser", "invalid hex digit");
    return -1; /* unreachable */
}

/* Decode a hex string into a malloc'd byte buffer (len may be 0). */
static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2 != 0) die("parser", "odd-length hex value");
    *out_len = n / 2;
    uint8_t *out = malloc(*out_len ? *out_len : 1);
    if (!out) die("parser", "out of memory");
    for (size_t i = 0; i < *out_len; i++) {
        out[i] = (uint8_t)((hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]));
    }
    return out;
}

/* Compare a CloakBuf-accumulated output against the expected bytes. */
static void expect_bytes(const char *vector, const char *mode, const uint8_t *got,
                         size_t got_len, const uint8_t *want, size_t want_len) {
    if (got_len != want_len || (want_len > 0 && memcmp(got, want, want_len) != 0)) {
        fprintf(stderr, "FAIL [%s] (%s): output diverges (got %zu bytes, want %zu)\n",
                vector, mode, got_len, want_len);
        exit(1);
    }
}

/* Append buf's bytes to a growable accumulator, then free buf. */
static void accum(uint8_t **acc, size_t *acc_len, struct CloakBuf buf) {
    if (buf.len > 0) {
        uint8_t *grown = realloc(*acc, *acc_len + buf.len);
        if (!grown) die("harness", "out of memory");
        memcpy(grown + *acc_len, buf.ptr, buf.len);
        *acc = grown;
        *acc_len += buf.len;
    }
    cloak_buf_free(buf);
}

/* Pre-sweep checks: ABI version, error paths, lifecycle refusals. */
static void check_abi_and_errors(void) {
    if (cloak_abi_version() != CLOAK_ABI_VERSION)
        die("abi", "cloak_abi_version() != CLOAK_ABI_VERSION");

    /* Bad TOML: NULL engine + message. */
    const char *bad = "not toml at all [[[";
    struct CloakBuf err = {NULL, 0};
    struct CloakEngine *engine =
        cloak_engine_new((const uint8_t *)bad, strlen(bad), &err);
    if (engine != NULL) die("errors", "bad config must be rejected");
    if (err.len == 0) die("errors", "rejection must carry a message");
    cloak_buf_free(err);

    /* {NULL, 0} buffer free is a no-op. */
    struct CloakBuf empty = {NULL, 0};
    cloak_buf_free(empty);

    /* Null handles error cleanly. */
    struct CloakBuf out = {NULL, 0};
    err.ptr = NULL;
    err.len = 0;
    if (cloak_redact(NULL, (const uint8_t *)"x", 1, &out, NULL, &err) != CLOAK_ERR)
        die("errors", "redact on NULL engine must return CLOAK_ERR");
    cloak_buf_free(out);
    cloak_buf_free(err);
    if (cloak_engine_free(NULL, NULL) != CLOAK_OK)
        die("errors", "engine_free(NULL) must be a no-op CLOAK_OK");
    cloak_session_free(NULL);
}

/* Lifecycle: engine_free refused while a session is live, then OK. */
static void check_lifecycle(struct CloakEngine *engine) {
    struct CloakBuf err = {NULL, 0};
    struct CloakSession *session = cloak_session_new(engine, &err);
    if (!session) die_err("lifecycle", "session_new failed", err);

    if (cloak_engine_free(engine, &err) != CLOAK_ERR)
        die("lifecycle", "engine_free must refuse while a session is live");
    cloak_buf_free(err);

    /* Aborting the session lifts the pin (verified by main's final free). */
    cloak_session_free(session);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <vectors.json>\n", argv[0]);
        return 2;
    }

    check_abi_and_errors();

    struct CloakBuf err = {NULL, 0};
    struct CloakEngine *engine =
        cloak_engine_new((const uint8_t *)CONFIG, strlen(CONFIG), &err);
    if (!engine) die_err("setup", "engine_new failed", err);

    check_lifecycle(engine);

    char *json = read_file(argv[1]);
    char *p = json;
    int count = 0;

    char *obj;
    while ((obj = strchr(p, '{')) != NULL) {
        char *end = strchr(obj, '}');
        if (!end) die("parser", "unterminated object");
        /* NUL-terminate the object so key lookups cannot run past it
         * (restored below) — this makes the parse key-order-independent. */
        *end = '\0';

        const char *key = strstr(obj, "\"name\"");
        if (!key) die("parser", "object missing name field");
        const char *q = key + strlen("\"name\"");
        char *name = read_quoted_value(&q);

        key = strstr(obj, "\"input\"");
        if (!key) die(name, "missing input field");
        q = key + strlen("\"input\"");
        char *input_hex = read_quoted_value(&q);

        key = strstr(obj, "\"expected\"");
        if (!key) die(name, "missing expected field");
        q = key + strlen("\"expected\"");
        char *expected_hex = read_quoted_value(&q);

        *end = '}';
        p = end + 1;

        size_t input_len, expected_len;
        uint8_t *input = hex_decode(input_hex, &input_len);
        uint8_t *expected = hex_decode(expected_hex, &expected_len);
        const uint8_t *input_ptr = input_len > 0 ? input : NULL;

        /* One-shot. */
        struct CloakBuf out = {NULL, 0};
        struct CloakBuf stats = {NULL, 0};
        err.ptr = NULL;
        err.len = 0;
        if (cloak_redact(engine, input_ptr, input_len, &out, &stats, &err) != CLOAK_OK)
            die_err(name, "redact failed", err);
        expect_bytes(name, "one-shot", out.ptr, out.len, expected, expected_len);
        if (stats.len == 0) die(name, "redact must produce stats JSON");
        cloak_buf_free(out);
        cloak_buf_free(stats);

        /* Streamed: four slices split at 1/4, 1/2, 3/4. */
        struct CloakSession *session = cloak_session_new(engine, &err);
        if (!session) die_err(name, "session_new failed", err);

        uint8_t *acc = NULL;
        size_t acc_len = 0;
        size_t cuts[5] = {0, input_len / 4, input_len / 2, 3 * input_len / 4, input_len};
        for (int i = 0; i < 4; i++) {
            size_t len = cuts[i + 1] - cuts[i];
            const uint8_t *chunk = len > 0 ? input + cuts[i] : NULL;
            out.ptr = NULL;
            out.len = 0;
            if (cloak_session_push(session, chunk, len, &out, &err) != CLOAK_OK)
                die_err(name, "push failed", err);
            accum(&acc, &acc_len, out);
        }
        out.ptr = NULL;
        out.len = 0;
        stats.ptr = NULL;
        stats.len = 0;
        if (cloak_session_finish(session, &out, &stats, &err) != CLOAK_OK)
            die_err(name, "finish failed", err);
        accum(&acc, &acc_len, out);
        cloak_buf_free(stats);
        cloak_session_free(session);

        expect_bytes(name, "streamed", acc, acc_len, expected, expected_len);

        free(acc);
        free(input);
        free(expected);
        free(input_hex);
        free(expected_hex);
        free(name);
        count++;
    }

    free(json);

    err.ptr = NULL;
    err.len = 0;
    if (cloak_engine_free(engine, &err) != CLOAK_OK)
        die_err("teardown", "engine_free failed", err);

    if (count == 0) die("harness", "no vectors found — wrong file?");
    printf("parity ok: %d vectors\n", count);
    return 0;
}
