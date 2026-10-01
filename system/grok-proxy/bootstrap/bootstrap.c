#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#ifndef GROK_BOOTSTRAP_KEY_ID
#error "GROK_BOOTSTRAP_KEY_ID is required"
#endif

#ifndef GROK_BOOTSTRAP_PUBLIC_KEY_HEX
#error "GROK_BOOTSTRAP_PUBLIC_KEY_HEX is required"
#endif

#ifndef GROK_BOOTSTRAP_TEST_BUILD
#define GROK_BOOTSTRAP_TEST_BUILD 0
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif

#define MANIFEST_NAME "release-manifest.txt"
#define SIGNATURE_NAME "release-manifest.sig"
#define BUNDLE_NAME "dispatcher.pyz"
#define SELECTOR_NAME "selected-release"
#define UPDATE_LOCK_NAME "update.lock"
#define PACKAGE_PENDING_NAME "package-update.pending"
#define MANIFEST_SCHEMA "grok-bootstrap-manifest-v1"
#define TRUST_ANCHOR_SCHEMA "grok-bootstrap-trust-anchor-v1"
#define PRODUCTION_PREFIX "/usr/local/libexec/grok-proxy/bootstrap-releases/"

#define PUBLIC_KEY_BYTES 32U
#define SIGNATURE_BYTES 64U
#define SHA256_BYTES 32U
#define SHA256_HEX_BYTES 64U
#define MAX_MANIFEST_BYTES (1024U * 1024U)
#define MAX_BUNDLE_BYTES (128U * 1024U * 1024U)
#define MAX_FILES 4096U
#define MAX_PATH_BYTES 512U

enum failure_code {
    FAILURE_USAGE,
    FAILURE_PATH_POLICY,
    FAILURE_PATH_METADATA,
    FAILURE_ARTIFACT_OPEN,
    FAILURE_ARTIFACT_METADATA,
    FAILURE_ARTIFACT_SIZE,
    FAILURE_KEY_CONFIGURATION,
    FAILURE_SIGNATURE_INVALID,
    FAILURE_MANIFEST_INVALID,
    FAILURE_BUNDLE_INVALID,
    FAILURE_SEAL,
    FAILURE_SELECTOR_AUTHORITY,
    FAILURE_PATH_CHANGED,
    FAILURE_TARGET_IDENTITY,
    FAILURE_TEST_HOOK,
    FAILURE_EXEC
};

struct artifact_set {
    int manifest_fd;
    int signature_fd;
    int bundle_fd;
    struct stat manifest_stat;
    struct stat signature_stat;
    struct stat bundle_stat;
};

struct selector_authority {
    int directory_fd;
    int lock_fd;
    int selector_fd;
    struct stat directory_stat;
    struct stat lock_stat;
    struct stat selector_stat;
    char release_id[SHA256_HEX_BYTES + 1U];
};

struct line_view {
    const unsigned char *data;
    size_t length;
};

struct manifest_cursor {
    const unsigned char *data;
    size_t length;
    size_t position;
};

struct manifest_info {
    uint64_t bundle_size;
    char bundle_sha256[SHA256_HEX_BYTES + 1U];
    char release_id[SHA256_HEX_BYTES + 1U];
};

static bool same_stat_identity(const struct stat *left,
                               const struct stat *right);

static _Noreturn void fail(enum failure_code code)
{
    const char *message;
    ssize_t ignored;

    switch (code) {
    case FAILURE_USAGE:
        message = "grok-bootstrap: USAGE\n";
        break;
    case FAILURE_PATH_POLICY:
        message = "grok-bootstrap: PATH_POLICY\n";
        break;
    case FAILURE_PATH_METADATA:
        message = "grok-bootstrap: PATH_METADATA\n";
        break;
    case FAILURE_ARTIFACT_OPEN:
        message = "grok-bootstrap: ARTIFACT_OPEN\n";
        break;
    case FAILURE_ARTIFACT_METADATA:
        message = "grok-bootstrap: ARTIFACT_METADATA\n";
        break;
    case FAILURE_ARTIFACT_SIZE:
        message = "grok-bootstrap: ARTIFACT_SIZE\n";
        break;
    case FAILURE_KEY_CONFIGURATION:
        message = "grok-bootstrap: KEY_CONFIGURATION\n";
        break;
    case FAILURE_SIGNATURE_INVALID:
        message = "grok-bootstrap: SIGNATURE_INVALID\n";
        break;
    case FAILURE_MANIFEST_INVALID:
        message = "grok-bootstrap: MANIFEST_INVALID\n";
        break;
    case FAILURE_BUNDLE_INVALID:
        message = "grok-bootstrap: BUNDLE_INVALID\n";
        break;
    case FAILURE_SEAL:
        message = "grok-bootstrap: SEAL_FAILURE\n";
        break;
    case FAILURE_SELECTOR_AUTHORITY:
        message = "grok-bootstrap: SELECTOR_AUTHORITY\n";
        break;
    case FAILURE_PATH_CHANGED:
        message = "grok-bootstrap: PATH_CHANGED\n";
        break;
    case FAILURE_TARGET_IDENTITY:
        message = "grok-bootstrap: TARGET_IDENTITY\n";
        break;
    case FAILURE_TEST_HOOK:
        message = "grok-bootstrap: TEST_HOOK_FAILURE\n";
        break;
    case FAILURE_EXEC:
    default:
        message = "grok-bootstrap: EXEC_FAILURE\n";
        break;
    }

    ignored = write(STDERR_FILENO, message, strlen(message));
    (void)ignored;
    _exit(126);
}

static bool initialize_crypto(void)
{
    static const char *const forbidden_environment[] = {
        "OPENSSL_CONF",
        "OPENSSL_CONF_INCLUDE",
        "OPENSSL_ENGINES",
        "OPENSSL_MODULES",
    };
    size_t index;

    for (index = 0U;
         index < sizeof(forbidden_environment) / sizeof(forbidden_environment[0]);
         ++index) {
        if (unsetenv(forbidden_environment[index]) != 0) {
            return false;
        }
    }
    return OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 1;
}

static bool is_lower_hex(const unsigned char *value, size_t length)
{
    size_t index;

    for (index = 0U; index < length; ++index) {
        const unsigned char byte = value[index];
        if (!((byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'f'))) {
            return false;
        }
    }
    return true;
}

static bool is_safe_key_id(const char *value)
{
    const size_t length = strlen(value);
    size_t index;

    if (length == 0U || length > 64U) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'.' || byte == (unsigned char)'_' ||
              byte == (unsigned char)'-')) {
            return false;
        }
    }
    return true;
}

static int hex_nibble(unsigned char byte)
{
    if (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') {
        return (int)(byte - (unsigned char)'0');
    }
    if (byte >= (unsigned char)'a' && byte <= (unsigned char)'f') {
        return (int)(byte - (unsigned char)'a') + 10;
    }
    return -1;
}

static bool decode_public_key(unsigned char output[PUBLIC_KEY_BYTES])
{
    const char *encoded = GROK_BOOTSTRAP_PUBLIC_KEY_HEX;
    size_t index;

    if (strlen(encoded) != SHA256_HEX_BYTES ||
        !is_lower_hex((const unsigned char *)encoded, SHA256_HEX_BYTES)) {
        return false;
    }
    for (index = 0U; index < PUBLIC_KEY_BYTES; ++index) {
        const int high = hex_nibble((unsigned char)encoded[index * 2U]);
        const int low = hex_nibble((unsigned char)encoded[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        output[index] = (unsigned char)((unsigned int)high * 16U +
                                       (unsigned int)low);
    }
    return true;
}

static bool extract_release_id(const char *path,
                               char release_id[SHA256_HEX_BYTES + 1U])
{
    const char *base;
    size_t length;

    if (path[0] != '/') {
        return false;
    }
#if GROK_BOOTSTRAP_TEST_BUILD
    base = strrchr(path, '/');
    if (base == NULL) {
        return false;
    }
    ++base;
#else
    length = strlen(PRODUCTION_PREFIX);
    if (strncmp(path, PRODUCTION_PREFIX, length) != 0) {
        return false;
    }
    base = path + length;
#endif
    length = strlen(base);
    if (length != SHA256_HEX_BYTES ||
        !is_lower_hex((const unsigned char *)base, length)) {
        return false;
    }
    memcpy(release_id, base, length);
    release_id[length] = '\0';
    return true;
}

#if !GROK_BOOTSTRAP_TEST_BUILD
static bool trusted_parent_metadata(const struct stat *information)
{
    return S_ISDIR(information->st_mode) && information->st_uid == (uid_t)0 &&
           information->st_gid == (gid_t)0 &&
           (information->st_mode & (mode_t)0022) == (mode_t)0;
}
#endif

static int open_release_directory(const char *path)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#else
    static const char *const components[] = {
        "usr", "local", "libexec", "grok-proxy", "bootstrap-releases"
    };
    const char *release_id = path + strlen(PRODUCTION_PREFIX);
    struct stat information;
    size_t index;
    int directory_fd;

    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 || fstat(directory_fd, &information) != 0 ||
        !trusted_parent_metadata(&information)) {
        if (directory_fd >= 0) {
            (void)close(directory_fd);
        }
        return -1;
    }

    for (index = 0U; index < sizeof(components) / sizeof(components[0]); ++index) {
        const int next_fd = openat(directory_fd, components[index],
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                       O_CLOEXEC);
        (void)close(directory_fd);
        directory_fd = next_fd;
        if (directory_fd < 0 || fstat(directory_fd, &information) != 0 ||
            !trusted_parent_metadata(&information)) {
            if (directory_fd >= 0) {
                (void)close(directory_fd);
            }
            return -1;
        }
    }

    {
        const int release_fd = openat(directory_fd, release_id,
                                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                          O_CLOEXEC);
        (void)close(directory_fd);
        return release_fd;
    }
#endif
}

static int open_selector_directory(void)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    const char *path = getenv("GROK_BOOTSTRAP_TEST_SELECTOR_DIR");
    if (path == NULL || path[0] != '/') {
        return -1;
    }
    return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#else
    static const char *const components[] = {
        "usr", "local", "libexec", "grok-proxy", "bootstrap"
    };
    struct stat information;
    size_t index;
    int directory_fd;

    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 || fstat(directory_fd, &information) != 0 ||
        !trusted_parent_metadata(&information)) {
        if (directory_fd >= 0) {
            (void)close(directory_fd);
        }
        return -1;
    }
    for (index = 0U; index < sizeof(components) / sizeof(components[0]); ++index) {
        const int next_fd = openat(directory_fd, components[index],
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                       O_CLOEXEC);
        (void)close(directory_fd);
        directory_fd = next_fd;
        if (directory_fd < 0 || fstat(directory_fd, &information) != 0 ||
            !trusted_parent_metadata(&information)) {
            if (directory_fd >= 0) {
                (void)close(directory_fd);
            }
            return -1;
        }
    }
    return directory_fd;
#endif
}

static bool expected_directory_metadata(const struct stat *information)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = (uid_t)0;
    const gid_t expected_gid = (gid_t)0;
#endif
    return S_ISDIR(information->st_mode) && information->st_uid == expected_uid &&
           information->st_gid == expected_gid &&
           information->st_nlink >= (nlink_t)2 &&
           (information->st_mode & (mode_t)07777) == (mode_t)0555;
}

static bool expected_artifact_metadata(const struct stat *information)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = (uid_t)0;
    const gid_t expected_gid = (gid_t)0;
#endif
    return S_ISREG(information->st_mode) && information->st_uid == expected_uid &&
           information->st_gid == expected_gid &&
           information->st_nlink == (nlink_t)1 &&
           (information->st_mode & (mode_t)07777) == (mode_t)0444;
}

static bool expected_selector_directory_metadata(const struct stat *information)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = (uid_t)0;
    const gid_t expected_gid = (gid_t)0;
#endif
    return S_ISDIR(information->st_mode) && information->st_uid == expected_uid &&
           information->st_gid == expected_gid &&
           information->st_nlink >= (nlink_t)2 &&
           (information->st_mode & (mode_t)0022) == (mode_t)0;
}

static bool expected_selector_metadata(const struct stat *information)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = (uid_t)0;
    const gid_t expected_gid = (gid_t)0;
#endif
    return S_ISREG(information->st_mode) && information->st_uid == expected_uid &&
           information->st_gid == expected_gid &&
           information->st_nlink == (nlink_t)1 &&
           information->st_size == (off_t)(SHA256_HEX_BYTES + 1U) &&
           (information->st_mode & (mode_t)07777) == (mode_t)0444;
}

static bool expected_update_lock_metadata(const struct stat *information)
{
#if GROK_BOOTSTRAP_TEST_BUILD
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = (uid_t)0;
    const gid_t expected_gid = (gid_t)0;
#endif
    return S_ISREG(information->st_mode) && information->st_uid == expected_uid &&
           information->st_gid == expected_gid &&
           information->st_nlink == (nlink_t)1 &&
           information->st_size == (off_t)0 &&
           (information->st_mode & (mode_t)07777) == (mode_t)0600;
}

static bool package_update_is_absent(int directory_fd)
{
    struct stat information;

    if (fstatat(directory_fd, PACKAGE_PENDING_NAME, &information,
                AT_SYMLINK_NOFOLLOW) == 0) {
        return false;
    }
    return errno == ENOENT;
}

static bool directory_has_closed_contents(int directory_fd)
{
    bool found_manifest = false;
    bool found_signature = false;
    bool found_bundle = false;
    struct dirent *entry;
    DIR *stream;
    int duplicate_fd;

    duplicate_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate_fd < 0) {
        return false;
    }
    stream = fdopendir(duplicate_fd);
    if (stream == NULL) {
        (void)close(duplicate_fd);
        return false;
    }

    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        if (strcmp(name, MANIFEST_NAME) == 0 && !found_manifest) {
            found_manifest = true;
        } else if (strcmp(name, SIGNATURE_NAME) == 0 && !found_signature) {
            found_signature = true;
        } else if (strcmp(name, BUNDLE_NAME) == 0 && !found_bundle) {
            found_bundle = true;
        } else {
            (void)closedir(stream);
            return false;
        }
        errno = 0;
    }
    if (errno != 0) {
        (void)closedir(stream);
        return false;
    }
    if (closedir(stream) != 0) {
        return false;
    }
    return found_manifest && found_signature && found_bundle;
}

static bool open_artifacts(int directory_fd, struct artifact_set *artifacts)
{
    const int flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;

    artifacts->manifest_fd = openat(directory_fd, MANIFEST_NAME, flags);
    artifacts->signature_fd = openat(directory_fd, SIGNATURE_NAME, flags);
    artifacts->bundle_fd = openat(directory_fd, BUNDLE_NAME, flags);
    return artifacts->manifest_fd >= 0 && artifacts->signature_fd >= 0 &&
           artifacts->bundle_fd >= 0;
}

static bool stat_artifacts(struct artifact_set *artifacts)
{
    return fstat(artifacts->manifest_fd, &artifacts->manifest_stat) == 0 &&
           fstat(artifacts->signature_fd, &artifacts->signature_stat) == 0 &&
           fstat(artifacts->bundle_fd, &artifacts->bundle_stat) == 0;
}

static bool artifacts_have_expected_metadata(const struct artifact_set *artifacts)
{
    return expected_artifact_metadata(&artifacts->manifest_stat) &&
           expected_artifact_metadata(&artifacts->signature_stat) &&
           expected_artifact_metadata(&artifacts->bundle_stat);
}

static bool artifacts_have_bounded_sizes(const struct artifact_set *artifacts)
{
    return artifacts->manifest_stat.st_size > (off_t)0 &&
           artifacts->manifest_stat.st_size <= (off_t)MAX_MANIFEST_BYTES &&
           artifacts->signature_stat.st_size == (off_t)SIGNATURE_BYTES &&
           artifacts->bundle_stat.st_size > (off_t)0 &&
           artifacts->bundle_stat.st_size <= (off_t)MAX_BUNDLE_BYTES;
}

static bool read_exact_file(int file_fd, unsigned char *output, size_t length)
{
    size_t offset = 0U;
    unsigned char extra;

    while (offset < length) {
        const ssize_t result = read(file_fd, output + offset, length - offset);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (result == 0) {
            return false;
        }
        offset += (size_t)result;
    }
    for (;;) {
        const ssize_t result = read(file_fd, &extra, 1U);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return result == 0;
    }
}

static bool read_selector_value(
    int selector_fd,
    char output[SHA256_HEX_BYTES + 1U]
)
{
    unsigned char raw[SHA256_HEX_BYTES + 1U];

    if (lseek(selector_fd, (off_t)0, SEEK_SET) != (off_t)0 ||
        !read_exact_file(selector_fd, raw, sizeof(raw)) ||
        !is_lower_hex(raw, SHA256_HEX_BYTES) ||
        raw[SHA256_HEX_BYTES] != (unsigned char)'\n') {
        return false;
    }
    memcpy(output, raw, SHA256_HEX_BYTES);
    output[SHA256_HEX_BYTES] = '\0';
    return true;
}

static void close_selector_authority(struct selector_authority *authority)
{
    if (authority->selector_fd >= 0) {
        (void)close(authority->selector_fd);
        authority->selector_fd = -1;
    }
    if (authority->lock_fd >= 0) {
        (void)close(authority->lock_fd);
        authority->lock_fd = -1;
    }
    if (authority->directory_fd >= 0) {
        (void)close(authority->directory_fd);
        authority->directory_fd = -1;
    }
}

static bool load_selector_authority(
    const char *requested_release_id,
    struct selector_authority *authority
)
{
    struct stat named_lock;
    struct stat named_selector;

    authority->directory_fd = open_selector_directory();
    if (authority->directory_fd < 0 ||
        fstat(authority->directory_fd, &authority->directory_stat) != 0 ||
        !expected_selector_directory_metadata(&authority->directory_stat) ||
        fstatat(authority->directory_fd, UPDATE_LOCK_NAME, &named_lock,
                AT_SYMLINK_NOFOLLOW) != 0) {
        close_selector_authority(authority);
        return false;
    }
    authority->lock_fd = openat(
        authority->directory_fd, UPDATE_LOCK_NAME,
        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
    );
    if (authority->lock_fd < 0 ||
        fstat(authority->lock_fd, &authority->lock_stat) != 0 ||
        !expected_update_lock_metadata(&authority->lock_stat) ||
        !same_stat_identity(&named_lock, &authority->lock_stat) ||
        flock(authority->lock_fd, LOCK_SH) != 0 ||
        !package_update_is_absent(authority->directory_fd) ||
        fstatat(authority->directory_fd, SELECTOR_NAME, &named_selector,
                AT_SYMLINK_NOFOLLOW) != 0) {
        close_selector_authority(authority);
        return false;
    }
    authority->selector_fd = openat(
        authority->directory_fd, SELECTOR_NAME,
        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
    );
    if (authority->selector_fd < 0 ||
        fstat(authority->selector_fd, &authority->selector_stat) != 0 ||
        !expected_selector_metadata(&authority->selector_stat) ||
        !same_stat_identity(&named_selector, &authority->selector_stat) ||
        !read_selector_value(authority->selector_fd, authority->release_id) ||
        strcmp(authority->release_id, requested_release_id) != 0) {
        close_selector_authority(authority);
        return false;
    }
    return true;
}

static bool verify_signature(const unsigned char public_key[PUBLIC_KEY_BYTES],
                             const unsigned char signature[SIGNATURE_BYTES],
                             const unsigned char *manifest,
                             size_t manifest_length)
{
    EVP_MD_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    bool verified = false;

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key,
                                      PUBLIC_KEY_BYTES);
    context = EVP_MD_CTX_new();
    if (key != NULL && context != NULL &&
        EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(context, signature, SIGNATURE_BYTES, manifest,
                         manifest_length) == 1) {
        verified = true;
    }
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return verified;
}

static bool next_line(struct manifest_cursor *cursor, struct line_view *line)
{
    const unsigned char *newline;
    size_t remaining;

    if (cursor->position >= cursor->length) {
        return false;
    }
    remaining = cursor->length - cursor->position;
    newline = memchr(cursor->data + cursor->position, '\n', remaining);
    if (newline == NULL) {
        return false;
    }
    line->data = cursor->data + cursor->position;
    line->length = (size_t)(newline - line->data);
    cursor->position += line->length + 1U;
    return line->length > 0U;
}

static bool line_equals(const struct line_view *line, const char *expected)
{
    const size_t length = strlen(expected);
    return line->length == length && memcmp(line->data, expected, length) == 0;
}

static bool line_value(const struct line_view *line,
                       const char *prefix,
                       const unsigned char **value,
                       size_t *value_length)
{
    const size_t prefix_length = strlen(prefix);
    if (line->length <= prefix_length ||
        memcmp(line->data, prefix, prefix_length) != 0) {
        return false;
    }
    *value = line->data + prefix_length;
    *value_length = line->length - prefix_length;
    return true;
}

static bool parse_decimal(const unsigned char *value,
                          size_t length,
                          uint64_t *result)
{
    uint64_t parsed = UINT64_C(0);
    size_t index;

    if (length == 0U || (length > 1U && value[0] == (unsigned char)'0')) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        const unsigned char byte = value[index];
        const uint64_t digit = (uint64_t)(byte - (unsigned char)'0');
        if (byte < (unsigned char)'0' || byte > (unsigned char)'9' ||
            parsed > (UINT64_MAX - digit) / UINT64_C(10)) {
            return false;
        }
        parsed = parsed * UINT64_C(10) + digit;
    }
    *result = parsed;
    return true;
}

static bool safe_manifest_path(const unsigned char *path, size_t length)
{
    size_t component_start = 0U;
    size_t index;

    if (length == 0U || length > MAX_PATH_BYTES ||
        path[0] == (unsigned char)'/' || path[length - 1U] == (unsigned char)'/') {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        const unsigned char byte = path[index];
        const bool safe =
            (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
            (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
            (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
            byte == (unsigned char)'/' || byte == (unsigned char)'.' ||
            byte == (unsigned char)'_' || byte == (unsigned char)'-';
        if (!safe) {
            return false;
        }
        if (byte == (unsigned char)'/') {
            const size_t component_length = index - component_start;
            if (component_length == 0U ||
                (component_length == 1U &&
                 path[component_start] == (unsigned char)'.') ||
                (component_length == 2U &&
                 path[component_start] == (unsigned char)'.' &&
                 path[component_start + 1U] == (unsigned char)'.')) {
                return false;
            }
            component_start = index + 1U;
        }
    }
    {
        const size_t component_length = length - component_start;
        return component_length != 0U &&
               !(component_length == 1U &&
                 path[component_start] == (unsigned char)'.') &&
               !(component_length == 2U &&
                 path[component_start] == (unsigned char)'.' &&
                 path[component_start + 1U] == (unsigned char)'.');
    }
}

static int compare_paths(const unsigned char *left,
                         size_t left_length,
                         const unsigned char *right,
                         size_t right_length)
{
    const size_t common = left_length < right_length ? left_length : right_length;
    const int comparison = memcmp(left, right, common);
    if (comparison != 0) {
        return comparison;
    }
    if (left_length < right_length) {
        return -1;
    }
    if (left_length > right_length) {
        return 1;
    }
    return 0;
}

static void digest_to_hex(const unsigned char digest[SHA256_BYTES],
                          char output[SHA256_HEX_BYTES + 1U])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < SHA256_BYTES; ++index) {
        output[index * 2U] = digits[digest[index] >> 4U];
        output[index * 2U + 1U] = digits[digest[index] & 0x0fU];
    }
    output[SHA256_HEX_BYTES] = '\0';
}

static bool parse_manifest(const unsigned char *manifest,
                           size_t manifest_length,
                           struct manifest_info *information)
{
    struct manifest_cursor cursor = {manifest, manifest_length, 0U};
    struct line_view line;
    const unsigned char *value;
    size_t value_length;
    uint64_t file_count_value;
    unsigned char previous_path[MAX_PATH_BYTES];
    size_t previous_path_length = 0U;
    bool have_previous_path = false;
    unsigned int main_count = 0U;
    EVP_MD_CTX *hash_context = NULL;
    unsigned char digest[SHA256_BYTES];
    unsigned int digest_length = 0U;
    char inventory_sha256[SHA256_HEX_BYTES + 1U];
    uint64_t index;
    size_t byte_index;
    bool valid = false;

    for (byte_index = 0U; byte_index < manifest_length; ++byte_index) {
        const unsigned char byte = manifest[byte_index];
        if (byte != (unsigned char)'\n' &&
            (byte < (unsigned char)' ' || byte > (unsigned char)'~')) {
            return false;
        }
    }

    if (!next_line(&cursor, &line) ||
        !line_equals(&line, "schema=" MANIFEST_SCHEMA) ||
        !next_line(&cursor, &line) || !line_value(&line, "key_id=", &value,
                                                  &value_length) ||
        value_length != strlen(GROK_BOOTSTRAP_KEY_ID) ||
        memcmp(value, GROK_BOOTSTRAP_KEY_ID, value_length) != 0 ||
        !next_line(&cursor, &line) || !line_value(&line, "release_id=", &value,
                                                  &value_length) ||
        value_length != SHA256_HEX_BYTES || !is_lower_hex(value, value_length)) {
        return false;
    }
    memcpy(information->release_id, value, value_length);
    information->release_id[value_length] = '\0';

    if (!next_line(&cursor, &line) ||
        !line_equals(&line, "bundle_name=" BUNDLE_NAME) ||
        !next_line(&cursor, &line) ||
        !line_value(&line, "bundle_size=", &value, &value_length) ||
        !parse_decimal(value, value_length, &information->bundle_size) ||
        information->bundle_size == UINT64_C(0) ||
        information->bundle_size > (uint64_t)MAX_BUNDLE_BYTES ||
        !next_line(&cursor, &line) ||
        !line_value(&line, "bundle_sha256=", &value, &value_length) ||
        value_length != SHA256_HEX_BYTES || !is_lower_hex(value, value_length)) {
        return false;
    }
    memcpy(information->bundle_sha256, value, value_length);
    information->bundle_sha256[value_length] = '\0';

    if (!next_line(&cursor, &line) ||
        !line_value(&line, "file_count=", &value, &value_length) ||
        !parse_decimal(value, value_length, &file_count_value) ||
        file_count_value == UINT64_C(0) ||
        file_count_value > (uint64_t)MAX_FILES) {
        return false;
    }

    hash_context = EVP_MD_CTX_new();
    if (hash_context == NULL || EVP_DigestInit_ex(hash_context, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(hash_context);
        return false;
    }

    for (index = UINT64_C(0); index < file_count_value; ++index) {
        const unsigned char *path;
        size_t path_length;

        if (!next_line(&cursor, &line) || line.length <= 75U ||
            memcmp(line.data, "file=", 5U) != 0 ||
            !(memcmp(line.data + 5U, "0644", 4U) == 0 ||
              memcmp(line.data + 5U, "0755", 4U) == 0) ||
            line.data[9U] != (unsigned char)':' ||
            !is_lower_hex(line.data + 10U, SHA256_HEX_BYTES) ||
            line.data[74U] != (unsigned char)':') {
            goto cleanup;
        }
        path = line.data + 75U;
        path_length = line.length - 75U;
        if (!safe_manifest_path(path, path_length) ||
            (have_previous_path &&
             compare_paths(previous_path, previous_path_length, path, path_length) >=
                 0)) {
            goto cleanup;
        }
        if (path_length == strlen("__main__.py") &&
            memcmp(path, "__main__.py", path_length) == 0) {
            ++main_count;
        }
        memcpy(previous_path, path, path_length);
        previous_path_length = path_length;
        have_previous_path = true;

        if (EVP_DigestUpdate(hash_context, line.data, line.length) != 1 ||
            EVP_DigestUpdate(hash_context, "\n", 1U) != 1) {
            goto cleanup;
        }
    }

    if (cursor.position != cursor.length || main_count != 1U ||
        EVP_DigestFinal_ex(hash_context, digest, &digest_length) != 1 ||
        digest_length != SHA256_BYTES) {
        goto cleanup;
    }
    digest_to_hex(digest, inventory_sha256);
    if (memcmp(inventory_sha256, information->release_id,
               SHA256_HEX_BYTES + 1U) != 0) {
        goto cleanup;
    }
    valid = true;

cleanup:
    EVP_MD_CTX_free(hash_context);
    return valid;
}

static bool write_all(int file_fd, const unsigned char *data, size_t length)
{
    size_t offset = 0U;
    while (offset < length) {
        const ssize_t result = write(file_fd, data + offset, length - offset);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (result == 0) {
            return false;
        }
        offset += (size_t)result;
    }
    return true;
}

static int copy_bundle_to_sealed_memfd(int bundle_fd,
                                       const struct manifest_info *manifest)
{
    unsigned char buffer[64U * 1024U];
    unsigned char digest[SHA256_BYTES];
    unsigned int digest_length = 0U;
    char digest_hex[SHA256_HEX_BYTES + 1U];
    uint64_t total = UINT64_C(0);
    EVP_MD_CTX *hash_context = NULL;
    int memory_fd = -1;
    bool complete = false;

#if GROK_BOOTSTRAP_TEST_BUILD
    if (getenv("GROK_BOOTSTRAP_TEST_FORCE_MEMFD_FALLBACK") != NULL) {
        errno = EINVAL;
    } else
#endif
    {
        memory_fd = memfd_create(
            "grok-dispatcher",
            MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL
        );
    }
    if (memory_fd < 0 && errno == EINVAL) {
        /* Compatibility with kernels predating MFD_NOEXEC_SEAL. */
        memory_fd = memfd_create(
            "grok-dispatcher", MFD_CLOEXEC | MFD_ALLOW_SEALING
        );
    }
    if (memory_fd >= 0 && fchmod(memory_fd, (mode_t)0600) != 0) {
        (void)close(memory_fd);
        memory_fd = -1;
    }
    hash_context = EVP_MD_CTX_new();
    if (memory_fd < 0 || hash_context == NULL ||
        EVP_DigestInit_ex(hash_context, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }

    for (;;) {
        const ssize_t result = read(bundle_fd, buffer, sizeof(buffer));
        size_t count;
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto cleanup;
        }
        if (result == 0) {
            break;
        }
        count = (size_t)result;
        if (total > manifest->bundle_size ||
            (uint64_t)count > manifest->bundle_size - total ||
            EVP_DigestUpdate(hash_context, buffer, count) != 1 ||
            !write_all(memory_fd, buffer, count)) {
            goto cleanup;
        }
        total += (uint64_t)count;
    }
    if (total != manifest->bundle_size ||
        EVP_DigestFinal_ex(hash_context, digest, &digest_length) != 1 ||
        digest_length != SHA256_BYTES) {
        goto cleanup;
    }
    digest_to_hex(digest, digest_hex);
    if (memcmp(digest_hex, manifest->bundle_sha256,
               SHA256_HEX_BYTES + 1U) != 0 ||
        lseek(memory_fd, (off_t)0, SEEK_SET) != (off_t)0 ||
        fcntl(memory_fd, F_ADD_SEALS,
              F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        goto cleanup;
    }
    {
        const int seals = fcntl(memory_fd, F_GET_SEALS);
        const int expected = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        if (seals < 0 || (seals & expected) != expected) {
            goto cleanup;
        }
    }
    complete = true;

cleanup:
    EVP_MD_CTX_free(hash_context);
    if (!complete && memory_fd >= 0) {
        (void)close(memory_fd);
        memory_fd = -1;
    }
    return memory_fd;
}

static bool same_stat_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
           left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
           left->st_size == right->st_size &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static bool recheck_selector_authority(
    const struct selector_authority *authority
)
{
    char release_id[SHA256_HEX_BYTES + 1U];
    struct stat current_directory;
    struct stat held_lock;
    struct stat held_selector;
    struct stat current_lock;
    struct stat current_selector;
    int directory_fd = -1;
    int lock_fd = -1;
    int selector_fd = -1;
    bool matches = false;

    directory_fd = open_selector_directory();
    if (directory_fd >= 0 &&
        fstat(directory_fd, &current_directory) == 0 &&
        expected_selector_directory_metadata(&current_directory) &&
        same_stat_identity(&authority->directory_stat, &current_directory) &&
        package_update_is_absent(directory_fd) &&
        fstat(authority->lock_fd, &held_lock) == 0 &&
        expected_update_lock_metadata(&held_lock) &&
        same_stat_identity(&authority->lock_stat, &held_lock)) {
        lock_fd = openat(
            directory_fd, UPDATE_LOCK_NAME,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        );
    }
    if (lock_fd >= 0 &&
        fstat(lock_fd, &current_lock) == 0 &&
        expected_update_lock_metadata(&current_lock) &&
        same_stat_identity(&authority->lock_stat, &current_lock) &&
        fstat(authority->selector_fd, &held_selector) == 0 &&
        expected_selector_metadata(&held_selector) &&
        same_stat_identity(&authority->selector_stat, &held_selector)) {
        selector_fd = openat(
            directory_fd, SELECTOR_NAME,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        );
    }
    if (selector_fd >= 0 &&
        fstat(selector_fd, &current_selector) == 0 &&
        expected_selector_metadata(&current_selector) &&
        same_stat_identity(&authority->selector_stat, &current_selector) &&
        read_selector_value(selector_fd, release_id) &&
        strcmp(release_id, authority->release_id) == 0) {
        matches = true;
    }
    if (selector_fd >= 0) {
        (void)close(selector_fd);
    }
    if (lock_fd >= 0) {
        (void)close(lock_fd);
    }
    if (directory_fd >= 0) {
        (void)close(directory_fd);
    }
    return matches;
}

static bool recheck_artifact(int directory_fd,
                             const char *name,
                             const struct stat *original)
{
    const int file_fd = openat(directory_fd, name,
                               O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat current;
    bool matches = false;

    if (file_fd >= 0 && fstat(file_fd, &current) == 0 &&
        expected_artifact_metadata(&current) && same_stat_identity(original, &current)) {
        matches = true;
    }
    if (file_fd >= 0) {
        (void)close(file_fd);
    }
    return matches;
}

static bool recheck_release_path(const char *path,
                                 const struct stat *original_directory,
                                 const struct artifact_set *artifacts)
{
    const int directory_fd = open_release_directory(path);
    struct stat current_directory;
    bool matches = false;

    if (directory_fd >= 0 && fstat(directory_fd, &current_directory) == 0 &&
        expected_directory_metadata(&current_directory) &&
        same_stat_identity(original_directory, &current_directory) &&
        directory_has_closed_contents(directory_fd) &&
        recheck_artifact(directory_fd, MANIFEST_NAME,
                         &artifacts->manifest_stat) &&
        recheck_artifact(directory_fd, SIGNATURE_NAME,
                         &artifacts->signature_stat) &&
        recheck_artifact(directory_fd, BUNDLE_NAME, &artifacts->bundle_stat)) {
        matches = true;
    }
    if (directory_fd >= 0) {
        (void)close(directory_fd);
    }
    return matches;
}

#if GROK_BOOTSTRAP_TEST_BUILD
static bool parse_test_fd(const char *name, int *file_fd)
{
    const char *value = getenv(name);
    uint64_t parsed = UINT64_C(0);
    size_t index;

    if (value == NULL || value[0] == '\0') {
        return false;
    }
    for (index = 0U; value[index] != '\0'; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        const uint64_t digit = (uint64_t)(byte - (unsigned char)'0');
        if (byte < (unsigned char)'0' || byte > (unsigned char)'9' ||
            parsed > (uint64_t)INT_MAX ||
            parsed > (UINT64_MAX - digit) / UINT64_C(10)) {
            return false;
        }
        parsed = parsed * UINT64_C(10) + digit;
    }
    if (parsed > (uint64_t)INT_MAX) {
        return false;
    }
    *file_fd = (int)parsed;
    return true;
}

static bool test_replacement_barrier(void)
{
    const char *ready_value = getenv("GROK_BOOTSTRAP_TEST_READY_FD");
    const char *continue_value = getenv("GROK_BOOTSTRAP_TEST_CONTINUE_FD");
    unsigned char byte = (unsigned char)'R';
    int ready_fd;
    int continue_fd;
    ssize_t result;

    if (ready_value == NULL && continue_value == NULL) {
        return true;
    }
    if (!parse_test_fd("GROK_BOOTSTRAP_TEST_READY_FD", &ready_fd) ||
        !parse_test_fd("GROK_BOOTSTRAP_TEST_CONTINUE_FD", &continue_fd) ||
        !write_all(ready_fd, &byte, 1U)) {
        return false;
    }
    do {
        result = read(continue_fd, &byte, 1U);
    } while (result < 0 && errno == EINTR);
    return result == 1;
}

static bool test_exec_barrier(void)
{
    const char *ready_value = getenv("GROK_BOOTSTRAP_TEST_EXEC_READY_FD");
    const char *continue_value = getenv("GROK_BOOTSTRAP_TEST_EXEC_CONTINUE_FD");
    unsigned char byte = (unsigned char)'E';
    int ready_fd;
    int continue_fd;
    ssize_t result;

    if (ready_value == NULL && continue_value == NULL) {
        return true;
    }
    if (!parse_test_fd("GROK_BOOTSTRAP_TEST_EXEC_READY_FD", &ready_fd) ||
        !parse_test_fd("GROK_BOOTSTRAP_TEST_EXEC_CONTINUE_FD", &continue_fd) ||
        !write_all(ready_fd, &byte, 1U)) {
        return false;
    }
    do {
        result = read(continue_fd, &byte, 1U);
    } while (result < 0 && errno == EINTR);
    return result == 1;
}
#endif

static bool mark_inherited_descriptors_cloexec(void)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, CLOSE_RANGE_CLOEXEC) == 0) {
        return true;
    }
#endif
    {
        DIR *stream = opendir("/proc/self/fd");
        struct dirent *entry;
        int scan_fd;

        if (stream == NULL) {
            return false;
        }
        scan_fd = dirfd(stream);
        errno = 0;
        while ((entry = readdir(stream)) != NULL) {
            uint64_t parsed = UINT64_C(0);
            size_t index;
            bool numeric = entry->d_name[0] != '\0';

            for (index = 0U; entry->d_name[index] != '\0'; ++index) {
                const unsigned char byte = (unsigned char)entry->d_name[index];
                if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
                    numeric = false;
                    break;
                }
                parsed = parsed * UINT64_C(10) +
                         (uint64_t)(byte - (unsigned char)'0');
                if (parsed > (uint64_t)INT_MAX) {
                    numeric = false;
                    break;
                }
            }
            if (numeric && parsed >= UINT64_C(3) && (int)parsed != scan_fd) {
                const int descriptor = (int)parsed;
                const int flags = fcntl(descriptor, F_GETFD);
                if (flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0) {
                    (void)closedir(stream);
                    return false;
                }
                if (flags < 0 && errno != EBADF) {
                    (void)closedir(stream);
                    return false;
                }
            }
            errno = 0;
        }
        if (errno != 0 || closedir(stream) != 0) {
            return false;
        }
    }
    return true;
}

static bool prepare_target_identity(char *output, size_t output_size)
{
    const char *raw;
    uintmax_t parsed = UINTMAX_C(0);
    uid_t target_uid;
    struct passwd account;
    struct passwd *result = NULL;
    char account_buffer[16U * 1024U];
    size_t index;
    int length;
    bool root_invocation = geteuid() == (uid_t)0;

    output[0] = '\0';
#if GROK_BOOTSTRAP_TEST_BUILD
    {
        const char *assume_root = getenv("GROK_BOOTSTRAP_TEST_ASSUME_ROOT");
        if (assume_root != NULL) {
            if (strcmp(assume_root, "1") != 0) {
                return false;
            }
            root_invocation = true;
        }
    }
#endif
    if (!root_invocation) {
        return true;
    }
    raw = getenv("SUDO_UID");
    if (raw == NULL || raw[0] == '\0' || raw[0] == (char)'0') {
        return false;
    }
    for (index = 0U; raw[index] != '\0'; ++index) {
        const unsigned char byte = (unsigned char)raw[index];
        const uintmax_t digit = (uintmax_t)(byte - (unsigned char)'0');
        if (index >= 20U || byte < (unsigned char)'0' ||
            byte > (unsigned char)'9' ||
            parsed > (UINTMAX_MAX - digit) / UINTMAX_C(10)) {
            return false;
        }
        parsed = parsed * UINTMAX_C(10) + digit;
    }
    if (parsed == UINTMAX_C(0)) {
        return false;
    }
    target_uid = (uid_t)parsed;
    if ((uintmax_t)target_uid != parsed ||
        getpwuid_r(target_uid, &account, account_buffer, sizeof(account_buffer),
                   &result) != 0 ||
        result == NULL || result->pw_uid != target_uid ||
        result->pw_name == NULL || result->pw_name[0] == '\0' ||
        result->pw_dir == NULL || result->pw_dir[0] != '/' ||
        strcmp(result->pw_dir, "/") == 0) {
        return false;
    }
    length = snprintf(output, output_size, "SUDO_UID=%" PRIuMAX, parsed);
    return length > 0 && (size_t)length < output_size;
}

static _Noreturn void execute_bundle(
    int memory_fd,
    int argc,
    char **argv,
    struct selector_authority *selector
)
{
    char authority_environment[64];
    char descriptor_path[64];
    char target_identity[64];
    char **execution_argv;
    char *clean_environment[] = {
        "PATH=/usr/bin:/bin",
        "LANG=C",
        "LC_ALL=C",
        "PYTHONDONTWRITEBYTECODE=1",
        NULL,
        NULL,
        NULL
    };
    int descriptor_flags;
    int verification_fd;
    struct stat memory_stat;
    struct stat verification_stat;
    int index;
    const int authority_length = snprintf(
        authority_environment,
        sizeof(authority_environment),
        "GROK_BOOTSTRAP_AUTHORITY_FD=%d",
        memory_fd
    );
    const int path_length = snprintf(descriptor_path, sizeof(descriptor_path),
                                     "/proc/self/fd/%d", memory_fd);

    if (authority_length < 0 ||
        (size_t)authority_length >= sizeof(authority_environment)) {
        fail(FAILURE_EXEC);
    }
    clean_environment[4] = authority_environment;
    if (!prepare_target_identity(target_identity, sizeof(target_identity))) {
        fail(FAILURE_TARGET_IDENTITY);
    }
    if (target_identity[0] != '\0') {
        clean_environment[5] = target_identity;
    }
    if (path_length < 0 || (size_t)path_length >= sizeof(descriptor_path)) {
        fail(FAILURE_EXEC);
    }
    verification_fd = open(descriptor_path, O_RDONLY | O_CLOEXEC);
    if (verification_fd < 0 || fstat(memory_fd, &memory_stat) != 0 ||
        fstat(verification_fd, &verification_stat) != 0 ||
        memory_stat.st_dev != verification_stat.st_dev ||
        memory_stat.st_ino != verification_stat.st_ino) {
        if (verification_fd >= 0) {
            (void)close(verification_fd);
        }
        fail(FAILURE_EXEC);
    }
    (void)close(verification_fd);
    if (!mark_inherited_descriptors_cloexec()) {
        fail(FAILURE_EXEC);
    }
    descriptor_flags = fcntl(memory_fd, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(memory_fd, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
        fail(FAILURE_EXEC);
    }

    execution_argv = calloc((size_t)argc + 2U, sizeof(*execution_argv));
    if (execution_argv == NULL) {
        fail(FAILURE_EXEC);
    }
    execution_argv[0] = "/usr/bin/python3";
    execution_argv[1] = "-I";
    execution_argv[2] = "-B";
    execution_argv[3] = "-S";
    execution_argv[4] = descriptor_path;
    for (index = 4; index < argc; ++index) {
        execution_argv[(size_t)index + 1U] = argv[index];
    }
    execution_argv[(size_t)argc + 1U] = NULL;

    (void)umask((mode_t)0077);
    if (chdir("/") != 0) {
        fail(FAILURE_EXEC);
    }
    if (!recheck_selector_authority(selector)) {
        fail(FAILURE_SELECTOR_AUTHORITY);
    }
#if GROK_BOOTSTRAP_TEST_BUILD
    if (!test_exec_barrier()) {
        fail(FAILURE_TEST_HOOK);
    }
#endif
    /* Keep the shared update lock until successful exec closes it. */
    execve("/usr/bin/python3", execution_argv, clean_environment);
    fail(FAILURE_EXEC);
}

int main(int argc, char **argv)
{
    unsigned char public_key[PUBLIC_KEY_BYTES];
    unsigned char signature[SIGNATURE_BYTES];
    unsigned char *manifest;
    char path_release_id[SHA256_HEX_BYTES + 1U];
    struct manifest_info manifest_information;
    struct artifact_set artifacts = {-1, -1, -1, {0}, {0}, {0}};
    struct selector_authority selector = {
        .directory_fd = -1,
        .lock_fd = -1,
        .selector_fd = -1,
    };
    struct stat directory_stat;
    const char *release_path;
    size_t manifest_length;
    int directory_fd;
    int memory_fd;

    if (!initialize_crypto()) {
        fail(FAILURE_KEY_CONFIGURATION);
    }
    if (argc == 2 && strcmp(argv[1], "--describe-trust-anchor") == 0) {
        if (!is_safe_key_id(GROK_BOOTSTRAP_KEY_ID) ||
            !decode_public_key(public_key)) {
            fail(FAILURE_KEY_CONFIGURATION);
        }
        if (printf("{\"key_id\":\"%s\",\"public_key_hex\":\"%s\","
                   "\"schema_version\":\"%s\"}\n",
                   GROK_BOOTSTRAP_KEY_ID,
                   GROK_BOOTSTRAP_PUBLIC_KEY_HEX,
                   TRUST_ANCHOR_SCHEMA) < 0 ||
            fflush(stdout) != 0) {
            fail(FAILURE_EXEC);
        }
        return 0;
    }
#if !GROK_BOOTSTRAP_TEST_BUILD
    if (geteuid() != (uid_t)0) {
        fail(FAILURE_TARGET_IDENTITY);
    }
#endif
    if (argc < 4 || strcmp(argv[1], "--release-dir") != 0 ||
        strcmp(argv[3], "--") != 0) {
        fail(FAILURE_USAGE);
    }
    release_path = argv[2];
    if (!is_safe_key_id(GROK_BOOTSTRAP_KEY_ID) || !decode_public_key(public_key)) {
        fail(FAILURE_KEY_CONFIGURATION);
    }
    if (!extract_release_id(release_path, path_release_id)) {
        fail(FAILURE_PATH_POLICY);
    }
    if (!load_selector_authority(path_release_id, &selector)) {
        fail(FAILURE_SELECTOR_AUTHORITY);
    }

    directory_fd = open_release_directory(release_path);
    if (directory_fd < 0 || fstat(directory_fd, &directory_stat) != 0 ||
        !expected_directory_metadata(&directory_stat) ||
        !directory_has_closed_contents(directory_fd)) {
        fail(FAILURE_PATH_METADATA);
    }
    if (!open_artifacts(directory_fd, &artifacts)) {
        fail(FAILURE_ARTIFACT_OPEN);
    }
    if (!stat_artifacts(&artifacts) ||
        !artifacts_have_expected_metadata(&artifacts)) {
        fail(FAILURE_ARTIFACT_METADATA);
    }
    if (!artifacts_have_bounded_sizes(&artifacts)) {
        fail(FAILURE_ARTIFACT_SIZE);
    }

#if GROK_BOOTSTRAP_TEST_BUILD
    if (!test_replacement_barrier()) {
        fail(FAILURE_TEST_HOOK);
    }
#endif

    manifest_length = (size_t)artifacts.manifest_stat.st_size;
    manifest = malloc(manifest_length);
    if (manifest == NULL ||
        !read_exact_file(artifacts.manifest_fd, manifest, manifest_length) ||
        !read_exact_file(artifacts.signature_fd, signature, SIGNATURE_BYTES)) {
        fail(FAILURE_ARTIFACT_SIZE);
    }
    if (!verify_signature(public_key, signature, manifest, manifest_length)) {
        fail(FAILURE_SIGNATURE_INVALID);
    }
    if (!parse_manifest(manifest, manifest_length, &manifest_information) ||
        memcmp(manifest_information.release_id, path_release_id,
               SHA256_HEX_BYTES + 1U) != 0) {
        fail(FAILURE_MANIFEST_INVALID);
    }
    free(manifest);

    if (manifest_information.bundle_size !=
        (uint64_t)artifacts.bundle_stat.st_size) {
        fail(FAILURE_BUNDLE_INVALID);
    }
    memory_fd = copy_bundle_to_sealed_memfd(artifacts.bundle_fd,
                                            &manifest_information);
    if (memory_fd < 0) {
        fail(FAILURE_BUNDLE_INVALID);
    }
    if (!recheck_release_path(release_path, &directory_stat, &artifacts)) {
        fail(FAILURE_PATH_CHANGED);
    }

    (void)close(artifacts.manifest_fd);
    (void)close(artifacts.signature_fd);
    (void)close(artifacts.bundle_fd);
    (void)close(directory_fd);
    execute_bundle(memory_fd, argc, argv, &selector);
}
