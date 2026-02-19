/**
 * @file hanzo_auth.c
 * @brief Example: Authenticate with ZT controller using Hanzo IAM JWT.
 *
 * This demonstrates the external JWT authentication flow:
 * 1. Resolve Hanzo credentials from env/file
 * 2. POST to controller /edge/client/v1/authenticate?method=ext-jwt
 * 3. Extract session token from response
 * 4. Use session token for subsequent API calls
 *
 * Build:
 *   gcc -o hanzo_auth hanzo_auth.c -lcurl
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TOKEN_LEN 4096
#define MAX_RESPONSE_LEN (64 * 1024)

struct response_buf {
    char data[MAX_RESPONSE_LEN];
    size_t len;
};

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct response_buf *buf = (struct response_buf *)userdata;
    size_t total = size * nmemb;
    if (buf->len + total >= MAX_RESPONSE_LEN) {
        return 0; /* signal error */
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/**
 * Resolve Hanzo credentials.
 * Checks HANZO_API_KEY env var, then ~/.hanzo/auth.json.
 * Returns the token string (caller must free), or NULL on failure.
 */
static char *resolve_hanzo_token(void)
{
    /* 1. Check env */
    const char *env_key = getenv("HANZO_API_KEY");
    if (env_key && env_key[0] != '\0') {
        return strdup(env_key);
    }

    /* 2. Check auth file */
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");
    }
    if (!home) {
        fprintf(stderr, "Cannot determine home directory\n");
        return NULL;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/.hanzo/auth.json", home);

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "No credentials found — set HANZO_API_KEY or run `dev login`\n");
        return NULL;
    }

    char content[MAX_TOKEN_LEN * 2];
    size_t n = fread(content, 1, sizeof(content) - 1, f);
    fclose(f);
    content[n] = '\0';

    /* Simple JSON token extraction (for demo — use a proper JSON parser in production) */
    const char *token_key = "\"token\"";
    char *p = strstr(content, token_key);
    if (!p) {
        token_key = "\"api_key\"";
        p = strstr(content, token_key);
    }
    if (!p) {
        fprintf(stderr, "No token found in %s\n", path);
        return NULL;
    }

    /* Skip to value */
    p = strchr(p, ':');
    if (!p) return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '"') p++;

    char *end = strchr(p, '"');
    if (!end) return NULL;

    size_t token_len = (size_t)(end - p);
    char *token = (char *)malloc(token_len + 1);
    if (!token) return NULL;
    memcpy(token, p, token_len);
    token[token_len] = '\0';

    return token;
}

int main(int argc, char *argv[])
{
    const char *controller_url = argc > 1 ? argv[1] : "https://zt-api.hanzo.ai";

    /* Resolve credentials */
    char *token = resolve_hanzo_token();
    if (!token) {
        return 1;
    }

    if (strlen(token) > 8) {
        printf("Credentials: Hanzo API key (...%s)\n", token + strlen(token) - 5);
    } else {
        printf("Credentials: Hanzo API key (***)\n");
    }

    /* Init curl */
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to init curl\n");
        free(token);
        return 1;
    }

    /* Build URL */
    char url[512];
    snprintf(url, sizeof(url), "%s/edge/client/v1/authenticate?method=ext-jwt", controller_url);

    /* Build auth header */
    char auth_header[MAX_TOKEN_LEN + 32];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    /* Set up request */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);

    const char *body = "{\"configTypes\":[]}";
    struct response_buf resp = {.len = 0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    printf("Authenticating with %s ...\n", controller_url);
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Request failed: %s\n", curl_easy_strerror(res));
    } else {
        long status;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (status == 200) {
            printf("Authentication successful!\n");
            printf("Response: %.200s...\n", resp.data);
        } else {
            fprintf(stderr, "Authentication failed (%ld): %s\n", status, resp.data);
        }
    }

    /* Cleanup */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(token);

    return (res == CURLE_OK) ? 0 : 1;
}
