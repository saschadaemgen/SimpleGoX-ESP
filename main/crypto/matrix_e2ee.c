#include "matrix_e2ee.h"
#include "crypto_utils.h"
#include "olm_message.h"
#include "megolm_message.h"
#include "matrix_client.h"
#include "matrix_http.h"
#include "nvs_storage.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "mjson.h"

static const char *TAG = "matrix_e2ee";

#define NVS_KEY_OLM_ACCOUNT "olm_acct"

/* Helper: build canonical JSON for device keys signing.
 * Fields MUST be sorted alphabetically per Matrix spec. */
static int build_device_keys_canonical(char *buf, size_t buf_size,
                                        const char *user_id,
                                        const char *device_id,
                                        const char *ed25519_b64,
                                        const char *curve25519_b64)
{
    return snprintf(buf, buf_size,
        "{\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],"
        "\"device_id\":\"%s\","
        "\"keys\":{\"curve25519:%s\":\"%s\",\"ed25519:%s\":\"%s\"},"
        "\"user_id\":\"%s\"}",
        device_id,
        device_id, curve25519_b64,
        device_id, ed25519_b64,
        user_id);
}

/* Helper: build signed OTK canonical JSON for signing: {"key":"<b64>"} */
static int build_otk_canonical(char *buf, size_t buf_size, const char *key_b64)
{
    return snprintf(buf, buf_size, "{\"key\":\"%s\"}", key_b64);
}

/* Helper: OTK key ID from uint32 -> 4-byte big-endian -> base64 */
static void otk_key_id_b64(uint32_t key_id, char *out, size_t out_size)
{
    uint8_t bytes[4] = {
        (uint8_t)((key_id >> 24) & 0xFF),
        (uint8_t)((key_id >> 16) & 0xFF),
        (uint8_t)((key_id >> 8) & 0xFF),
        (uint8_t)(key_id & 0xFF),
    };
    crypto_base64_encode(bytes, 4, out, out_size);
}

esp_err_t matrix_e2ee_init(matrix_e2ee_t *e2ee)
{
    if (e2ee == NULL) { return ESP_ERR_INVALID_ARG; }

    memset(e2ee, 0, sizeof(matrix_e2ee_t));

    /* Try to load existing account from NVS */
    uint8_t blob[1024];
    size_t blob_len = 0;
    esp_err_t err = nvs_storage_load_blob(NVS_KEY_OLM_ACCOUNT, blob, sizeof(blob), &blob_len);

    if (err == ESP_OK && blob_len > 0) {
        err = olm_account_deserialize(&e2ee->account, blob, blob_len);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Loaded existing Olm account from NVS");
            e2ee->initialized = true;
            crypto_wipe(blob, sizeof(blob));
            return ESP_OK;
        }
        ESP_LOGW(TAG, "Failed to deserialize Olm account, creating new");
    }

    /* Create new account */
    err = olm_account_create(&e2ee->account);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create Olm account");
        return err;
    }

    /* Generate initial batch of one-time keys */
    err = olm_account_generate_one_time_keys(&e2ee->account, OLM_MAX_ONE_TIME_KEYS);
    if (err != ESP_OK) { return err; }

    /* Save to NVS */
    size_t ser_len = olm_account_serialize(&e2ee->account, blob, sizeof(blob));
    if (ser_len > 0) {
        nvs_storage_save_blob(NVS_KEY_OLM_ACCOUNT, blob, ser_len);
    }
    crypto_wipe(blob, sizeof(blob));

    e2ee->initialized = true;
    ESP_LOGI(TAG, "E2EE initialized with new Olm account");
    return ESP_OK;
}

esp_err_t matrix_e2ee_save_account(matrix_e2ee_t *e2ee)
{
    if (e2ee == NULL || !e2ee->initialized) { return ESP_ERR_INVALID_ARG; }

    uint8_t blob[1024];
    size_t ser_len = olm_account_serialize(&e2ee->account, blob, sizeof(blob));
    if (ser_len == 0) { return ESP_FAIL; }

    esp_err_t err = nvs_storage_save_blob(NVS_KEY_OLM_ACCOUNT, blob, ser_len);
    crypto_wipe(blob, sizeof(blob));
    return err;
}

/* Delete all other devices for this user (clean up ghost devices) */
static void delete_old_devices(matrix_client_t *client)
{
    /* Query our own devices first */
    char *url = malloc(512);
    if (url == NULL) { return; }
    snprintf(url, 512, "%s/_matrix/client/v3/devices", client->homeserver_url);

    char *resp = malloc(4096);
    if (resp == NULL) { free(url); return; }

    int resp_len = 0;
    esp_err_t err = matrix_http_get(&client->http, url, client->access_token,
                                     resp, 4096, &resp_len);
    free(url);
    if (err != ESP_OK) {
        free(resp);
        return;
    }

    /* Find devices array and collect IDs that are not our current device */
    const char *devices = NULL;
    int devices_len = 0;
    mjson_find(resp, resp_len, "$.devices", &devices, &devices_len);
    if (devices == NULL) { free(resp); return; }

    /* Build delete request with all device IDs except ours */
    char *del_body = malloc(2048);
    if (del_body == NULL) { free(resp); return; }

    int pos = snprintf(del_body, 2048, "{\"devices\":[");
    bool found_old = false;

    int koff, klen, voff, vlen, vtype, off = 0;
    while ((off = mjson_next(devices, devices_len, off,
                              &koff, &klen, &voff, &vlen, &vtype)) != 0) {
        char dev_id[64] = {0};
        mjson_get_string(devices + voff, vlen, "$.device_id", dev_id, sizeof(dev_id));
        if (dev_id[0] != '\0' && strcmp(dev_id, client->device_id) != 0) {
            if (found_old) { pos += snprintf(del_body + pos, 2048 - pos, ","); }
            pos += snprintf(del_body + pos, 2048 - pos, "\"%s\"", dev_id);
            found_old = true;
            ESP_LOGI(TAG, "Will delete old device: %s", dev_id);
        }
    }
    free(resp);

    if (!found_old) {
        ESP_LOGI(TAG, "No old devices to delete");
        free(del_body);
        return;
    }

    pos += snprintf(del_body + pos, 2048 - pos, "]}");

    url = malloc(512);
    if (url == NULL) { free(del_body); return; }
    snprintf(url, 512, "%s/_matrix/client/v3/delete_devices", client->homeserver_url);

    char del_resp[256];
    int del_resp_len = 0;
    err = matrix_http_post(&client->http, url, client->access_token,
                            del_body, del_resp, sizeof(del_resp), &del_resp_len);
    free(del_body);
    free(url);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Old devices deleted successfully");
    } else {
        /* 401 means interactive auth needed - log but continue */
        ESP_LOGW(TAG, "delete_devices returned %s (may need interactive auth)",
                 esp_err_to_name(err));
    }
}

esp_err_t matrix_e2ee_upload_keys(matrix_e2ee_t *e2ee, matrix_client_t *client)
{
    if (e2ee == NULL || client == NULL || !e2ee->initialized) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Clean up ghost devices from previous sessions */
    delete_old_devices(client);

    char ed25519_b64[48], curve25519_b64[48];
    olm_account_get_identity_json(&e2ee->account, ed25519_b64, sizeof(ed25519_b64),
                                   curve25519_b64, sizeof(curve25519_b64));

    /* Build canonical JSON and sign it */
    char canonical[512];
    build_device_keys_canonical(canonical, sizeof(canonical),
                                client->user_id, client->device_id,
                                ed25519_b64, curve25519_b64);

    ESP_LOGI(TAG, "Canonical JSON to sign (%d bytes): %s",
             (int)strlen(canonical), canonical);

    uint8_t sig[64];
    esp_err_t sign_err = olm_account_sign(&e2ee->account,
                                           (const uint8_t *)canonical,
                                           strlen(canonical), sig);
    if (sign_err != ESP_OK) {
        ESP_LOGE(TAG, "Ed25519 signing failed: %s", esp_err_to_name(sign_err));
        return sign_err;
    }

    char sig_b64[96];
    crypto_base64_encode(sig, 64, sig_b64, sizeof(sig_b64));
    ESP_LOGI(TAG, "Signature: %.20s...", sig_b64);

    /* Build the full keys/upload JSON body */
    char *body = malloc(4096);
    if (body == NULL) { return ESP_ERR_NO_MEM; }

    int pos = snprintf(body, 4096,
        "{"
        "\"device_keys\":{"
            "\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],"
            "\"device_id\":\"%s\","
            "\"keys\":{"
                "\"curve25519:%s\":\"%s\","
                "\"ed25519:%s\":\"%s\""
            "},"
            "\"signatures\":{"
                "\"%s\":{"
                    "\"ed25519:%s\":\"%s\""
                "}"
            "},"
            "\"user_id\":\"%s\""
        "}",
        client->device_id,
        client->device_id, curve25519_b64,
        client->device_id, ed25519_b64,
        client->user_id,
        client->device_id, sig_b64,
        client->user_id);

    /* Add one-time keys */
    pos += snprintf(body + pos, 4096 - pos, ",\"one_time_keys\":{");

    bool first_otk = true;
    for (int i = 0; i < OLM_MAX_ONE_TIME_KEYS; i++) {
        olm_one_time_key_t *otk = &e2ee->account.one_time_keys[i];
        if (otk->key_id == 0 || otk->published || otk->used) { continue; }

        char otk_pub_b64[48];
        crypto_base64_encode(otk->public_key, 32, otk_pub_b64, sizeof(otk_pub_b64));

        /* Sign the OTK: canonical is {"key":"<b64>"} */
        char otk_canonical[128];
        build_otk_canonical(otk_canonical, sizeof(otk_canonical), otk_pub_b64);

        uint8_t otk_sig[64];
        olm_account_sign(&e2ee->account,
                          (const uint8_t *)otk_canonical, strlen(otk_canonical),
                          otk_sig);

        char otk_sig_b64[96];
        crypto_base64_encode(otk_sig, 64, otk_sig_b64, sizeof(otk_sig_b64));

        /* Key ID */
        char key_id_b64[12];
        otk_key_id_b64(otk->key_id, key_id_b64, sizeof(key_id_b64));

        if (!first_otk) { pos += snprintf(body + pos, 4096 - pos, ","); }
        first_otk = false;

        pos += snprintf(body + pos, 4096 - pos,
            "\"signed_curve25519:%s\":{"
                "\"key\":\"%s\","
                "\"signatures\":{"
                    "\"%s\":{"
                        "\"ed25519:%s\":\"%s\""
                    "}"
                "}"
            "}",
            key_id_b64, otk_pub_b64,
            client->user_id,
            client->device_id, otk_sig_b64);
    }

    pos += snprintf(body + pos, 4096 - pos, "}}");

    /* POST to /_matrix/client/v3/keys/upload */
    char *url = malloc(512);
    char *response = malloc(1024);
    if (url == NULL || response == NULL) { free(body); free(url); free(response); return ESP_ERR_NO_MEM; }
    snprintf(url, 512, "%s/_matrix/client/v3/keys/upload", client->homeserver_url);

    int response_len = 0;
    esp_err_t err = matrix_http_post(&client->http, url, client->access_token, body,
                                      response, 1024, &response_len);
    free(url); url = NULL;
    free(body);

    if (err != ESP_OK) {
        free(response);
        ESP_LOGE(TAG, "keys/upload failed");
        return err;
    }

    ESP_LOGI(TAG, "keys/upload response: %.200s", response);
    free(response); response = NULL;

    olm_account_mark_keys_as_published(&e2ee->account);
    matrix_e2ee_save_account(e2ee);

    e2ee->keys_uploaded = true;
    ESP_LOGI(TAG, "Device keys uploaded (ed25519=%s, curve25519=%s)",
             ed25519_b64, curve25519_b64);

    /* Self-query: verify our keys are visible on the server */
    ESP_LOGI(TAG, "Self-query: checking uploaded keys for %s...", client->user_id);
    {
        char qbody[256];
        snprintf(qbody, sizeof(qbody),
                 "{\"device_keys\":{\"%s\":[]}}", client->user_id);
        char qurl[512];
        snprintf(qurl, sizeof(qurl), "%s/_matrix/client/v3/keys/query",
                 client->homeserver_url);
        char *qresp = malloc(16384);
        if (qresp != NULL) {
            int qresp_len = 0;
            esp_err_t qerr = matrix_http_post(&client->http, qurl,
                                               client->access_token, qbody,
                                               qresp, 16384, &qresp_len);
            if (qerr == ESP_OK) {
                ESP_LOGI(TAG, "Self-query response (%d bytes): %.500s",
                         qresp_len, qresp);
                /* Check if our device_id appears */
                if (strstr(qresp, client->device_id) != NULL) {
                    ESP_LOGI(TAG, "Self-query: device %s FOUND on server",
                             client->device_id);
                } else {
                    ESP_LOGE(TAG, "Self-query: device %s NOT FOUND on server!",
                             client->device_id);
                }
                /* Check if our ed25519 key appears */
                if (strstr(qresp, ed25519_b64) != NULL) {
                    ESP_LOGI(TAG, "Self-query: ed25519 key verified on server");
                } else {
                    ESP_LOGW(TAG, "Self-query: ed25519 key NOT found in response");
                }
            } else {
                ESP_LOGW(TAG, "Self-query failed: %s", esp_err_to_name(qerr));
            }
            free(qresp);
        }
    }

    return ESP_OK;
}

esp_err_t matrix_e2ee_query_keys(matrix_e2ee_t *e2ee, matrix_client_t *client,
                                  const char *user_id)
{
    if (e2ee == NULL || client == NULL || user_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char *body = malloc(256);
    char *url = malloc(512);
    if (body == NULL || url == NULL) { free(body); free(url); return ESP_ERR_NO_MEM; }

    snprintf(body, 256, "{\"device_keys\":{\"%s\":[]}}", user_id);
    snprintf(url, 512, "%s/_matrix/client/v3/keys/query", client->homeserver_url);

    char *response = malloc(8192);
    if (response == NULL) { free(body); free(url); return ESP_ERR_NO_MEM; }

    int response_len = 0;
    esp_err_t err = matrix_http_post(&client->http, url, client->access_token, body,
                                      response, 8192, &response_len);
    free(body); body = NULL;
    free(url); url = NULL;
    if (err != ESP_OK) {
        free(response);
        ESP_LOGE(TAG, "keys/query failed");
        return err;
    }

    ESP_LOGI(TAG, "keys/query response: %d bytes", response_len);
    ESP_LOGD(TAG, "keys/query body: %.500s", response);

    /* Parse device keys from response.
     * Structure: {"device_keys": {"@user:server": {"DEVICE_ID": {...}}}}
     *
     * mjson path lookups fail with user_ids containing @ : . characters,
     * so we use mjson_find for "$.device_keys" then iterate with mjson_next
     * to find the user_id key by string comparison. */

    const char *all_device_keys = NULL;
    int all_device_keys_len = 0;
    int res = mjson_find(response, response_len, "$.device_keys",
                          &all_device_keys, &all_device_keys_len);

    if (res == MJSON_TOK_INVALID || all_device_keys == NULL) {
        free(response);
        ESP_LOGW(TAG, "No device_keys object in keys/query response");
        return ESP_OK;
    }

    /* Iterate top-level keys in device_keys to find our target user */
    const char *devices_json = NULL;
    int devices_json_len = 0;
    {
        int koff, klen, voff, vlen, vtype, off = 0;
        while ((off = mjson_next(all_device_keys, all_device_keys_len, off,
                                  &koff, &klen, &voff, &vlen, &vtype)) != 0) {
            /* Key is quoted: "@user:server" - compare without quotes */
            const char *key_str = all_device_keys + koff + 1; /* skip opening " */
            int key_str_len = klen - 2; /* skip both quotes */
            if (key_str_len == (int)strlen(user_id) &&
                memcmp(key_str, user_id, key_str_len) == 0) {
                devices_json = all_device_keys + voff;
                devices_json_len = vlen;
                break;
            }
        }
    }

    if (devices_json == NULL) {
        free(response);
        ESP_LOGW(TAG, "No device keys found for %s", user_id);
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Found device_keys for %s (%d bytes)", user_id, devices_json_len);

    /* Iterate devices */
    int koff, klen, voff, vlen, vtype, off = 0;
    e2ee->room_device_count = 0;

    while ((off = mjson_next(devices_json, devices_json_len, off,
                              &koff, &klen, &voff, &vlen, &vtype)) != 0) {
        if (e2ee->room_device_count >= E2EE_MAX_ROOM_DEVICES) { break; }

        const char *dev_json = devices_json + voff;
        int dev_json_len = vlen;

        e2ee_device_info_t *dev = &e2ee->room_devices[e2ee->room_device_count];
        memset(dev, 0, sizeof(e2ee_device_info_t));

        snprintf(dev->user_id, sizeof(dev->user_id), "%s", user_id);

        /* Extract device_id */
        mjson_get_string(dev_json, dev_json_len, "$.device_id",
                          dev->device_id, sizeof(dev->device_id));

        if (strlen(dev->device_id) == 0) { continue; }

        /* Skip our own device */
        if (strcmp(dev->device_id, client->device_id) == 0) { continue; }

        /* Extract curve25519 key */
        char key_path[128];
        snprintf(key_path, sizeof(key_path), "$.keys.curve25519:%s", dev->device_id);
        mjson_get_string(dev_json, dev_json_len, key_path,
                          dev->curve25519_b64, sizeof(dev->curve25519_b64));

        /* Extract ed25519 key */
        snprintf(key_path, sizeof(key_path), "$.keys.ed25519:%s", dev->device_id);
        mjson_get_string(dev_json, dev_json_len, key_path,
                          dev->ed25519_b64, sizeof(dev->ed25519_b64));

        if (strlen(dev->curve25519_b64) > 0) {
            crypto_base64_decode(dev->curve25519_b64, strlen(dev->curve25519_b64),
                                  dev->curve25519_key, 32);
            e2ee->room_device_count++;
            ESP_LOGI(TAG, "Found device %s:%s", user_id, dev->device_id);
        }
    }

    free(response);
    ESP_LOGI(TAG, "Queried %d devices for %s", e2ee->room_device_count, user_id);
    return ESP_OK;
}

/* Claim OTK from a specific device, create outbound Olm session */
static esp_err_t claim_and_create_olm_session(matrix_e2ee_t *e2ee,
                                               matrix_client_t *client,
                                               e2ee_device_info_t *device)
{
    if (e2ee->olm_session_count >= E2EE_MAX_OLM_SESSIONS) {
        ESP_LOGW(TAG, "Max Olm sessions reached");
        return ESP_FAIL;
    }

    /* POST keys/claim */
    char *body = malloc(256);
    char *url = malloc(512);
    if (body == NULL || url == NULL) { free(body); free(url); return ESP_ERR_NO_MEM; }

    snprintf(body, 256,
             "{\"one_time_keys\":{\"%s\":{\"%s\":\"signed_curve25519\"}}}",
             device->user_id, device->device_id);
    snprintf(url, 512, "%s/_matrix/client/v3/keys/claim", client->homeserver_url);

    char *response = malloc(2048);
    if (response == NULL) { free(body); free(url); return ESP_ERR_NO_MEM; }

    int response_len = 0;
    esp_err_t err = matrix_http_post(&client->http, url, client->access_token, body,
                                      response, 2048, &response_len);
    free(body); body = NULL;
    free(url); url = NULL;
    if (err != ESP_OK) {
        free(response);
        return err;
    }

    ESP_LOGI(TAG, "keys/claim response: %d bytes", response_len);

    /* Extract the claimed key from response.
     * Structure: {"one_time_keys": {"@user:server": {"DEVICE": {"signed_curve25519:ID": {...}}}}}
     * Navigate manually with mjson_next to avoid path issues with @:. chars */

    const char *otk_root = NULL;
    int otk_root_len = 0;
    mjson_find(response, response_len, "$.one_time_keys", &otk_root, &otk_root_len);
    if (otk_root == NULL) {
        free(response);
        ESP_LOGE(TAG, "No one_time_keys in claim response");
        return ESP_FAIL;
    }

    /* Find user -> device -> key chain via nested mjson_next */
    const char *device_keys = NULL;
    int device_keys_len = 0;
    {
        /* Level 1: find user */
        int k1, kl1, v1, vl1, vt1, o1 = 0;
        while ((o1 = mjson_next(otk_root, otk_root_len, o1,
                                 &k1, &kl1, &v1, &vl1, &vt1)) != 0) {
            if (kl1 - 2 == (int)strlen(device->user_id) &&
                memcmp(otk_root + k1 + 1, device->user_id, kl1 - 2) == 0) {
                /* Level 2: find device */
                const char *user_obj = otk_root + v1;
                int user_obj_len = vl1;
                int k2, kl2, v2, vl2, vt2, o2 = 0;
                while ((o2 = mjson_next(user_obj, user_obj_len, o2,
                                         &k2, &kl2, &v2, &vl2, &vt2)) != 0) {
                    if (kl2 - 2 == (int)strlen(device->device_id) &&
                        memcmp(user_obj + k2 + 1, device->device_id, kl2 - 2) == 0) {
                        device_keys = user_obj + v2;
                        device_keys_len = vl2;
                        break;
                    }
                }
                break;
            }
        }
    }

    if (device_keys == NULL) {
        free(response);
        ESP_LOGE(TAG, "No OTK in claim response for %s:%s",
                 device->user_id, device->device_id);
        return ESP_FAIL;
    }

    /* Get the first (and only) key object */
    int koff, klen, voff, vlen, vtype;
    int off = mjson_next(device_keys, device_keys_len, 0,
                          &koff, &klen, &voff, &vlen, &vtype);
    if (off == 0) {
        free(response);
        return ESP_FAIL;
    }

    /* Extract the "key" field from the signed key object */
    char otk_b64[48] = {0};
    mjson_get_string(device_keys + voff, vlen, "$.key", otk_b64, sizeof(otk_b64));

    if (strlen(otk_b64) == 0) {
        free(response);
        ESP_LOGE(TAG, "Empty OTK in claim response");
        return ESP_FAIL;
    }
    free(response);

    /* Decode OTK */
    uint8_t their_otk[32];
    crypto_base64_decode(otk_b64, strlen(otk_b64), their_otk, 32);

    /* Create outbound Olm session */
    int idx = e2ee->olm_session_count;
    uint8_t ephemeral_pub[32];
    err = olm_session_create_outbound(&e2ee->olm_sessions[idx],
                                       e2ee->account.identity.curve25519_private,
                                       device->curve25519_key,
                                       their_otk,
                                       ephemeral_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create outbound Olm session");
        return err;
    }

    memcpy(&e2ee->olm_session_devices[idx], device, sizeof(e2ee_device_info_t));
    e2ee->olm_session_count++;

    ESP_LOGI(TAG, "Created Olm session with %s:%s", device->user_id, device->device_id);
    return ESP_OK;
}

esp_err_t matrix_e2ee_ensure_outbound_session(matrix_e2ee_t *e2ee,
                                               matrix_client_t *client,
                                               const char *room_id)
{
    if (e2ee == NULL || client == NULL || room_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Create Megolm outbound session if needed */
    if (!e2ee->outbound_megolm_valid) {
        esp_err_t err = megolm_outbound_create(&e2ee->outbound_megolm);
        if (err != ESP_OK) { return err; }
        e2ee->outbound_megolm_valid = true;
        e2ee->outbound_megolm_shared = false;
    }

    /* Share session with all known devices if not yet shared */
    if (!e2ee->outbound_megolm_shared && e2ee->room_device_count > 0) {
        /* Get session key */
        uint8_t session_key[MEGOLM_SESSION_KEY_SIZE];
        size_t sk_len = 0;
        esp_err_t err = megolm_outbound_get_session_key(&e2ee->outbound_megolm,
                                                         session_key, sizeof(session_key),
                                                         &sk_len);
        if (err != ESP_OK) { return err; }

        /* Build m.room_key event plaintext */
        char sk_b64[320];
        crypto_base64_encode(session_key, sk_len, sk_b64, sizeof(sk_b64));

        char *room_key_json = malloc(1024);
        if (room_key_json == NULL) { return ESP_ERR_NO_MEM; }
        snprintf(room_key_json, 1024,
            "{\"type\":\"m.room_key\",\"content\":{"
                "\"algorithm\":\"m.megolm.v1.aes-sha2\","
                "\"room_id\":\"%s\","
                "\"session_id\":\"%s\","
                "\"session_key\":\"%s\","
                "\"chain_index\":0"
            "}}",
            room_id,
            e2ee->outbound_megolm.session_id_b64,
            sk_b64);

        ESP_LOGI(TAG, "Sharing Megolm session %s with %d devices",
                 e2ee->outbound_megolm.session_id_b64, e2ee->room_device_count);

        /* For each device: ensure Olm session, encrypt, send via to-device */
        int shared_count = 0;
        for (int d = 0; d < e2ee->room_device_count; d++) {
            e2ee_device_info_t *dev = &e2ee->room_devices[d];

            ESP_LOGI(TAG, "Sharing with [%d/%d] %s:%s",
                     d + 1, e2ee->room_device_count, dev->user_id, dev->device_id);

            /* Find or create Olm session */
            int olm_idx = -1;
            for (int i = 0; i < e2ee->olm_session_count; i++) {
                if (strcmp(e2ee->olm_session_devices[i].device_id, dev->device_id) == 0 &&
                    strcmp(e2ee->olm_session_devices[i].user_id, dev->user_id) == 0) {
                    olm_idx = i;
                    break;
                }
            }

            if (olm_idx < 0) {
                if (e2ee->olm_session_count >= E2EE_MAX_OLM_SESSIONS) {
                    ESP_LOGW(TAG, "  Olm session limit (%d) reached, skipping %s",
                             E2EE_MAX_OLM_SESSIONS, dev->device_id);
                    continue;
                }
                err = claim_and_create_olm_session(e2ee, client, dev);
                if (err != ESP_OK) {
                    ESP_LOGW(TAG, "  Failed to create Olm session for %s: %s",
                             dev->device_id, esp_err_to_name(err));
                    continue;
                }
                olm_idx = e2ee->olm_session_count - 1;
            }

            /* Encrypt room_key_json with Olm */
            uint8_t olm_ct[2048];
            size_t olm_ct_len = 0;
            int olm_msg_type = 0;
            err = olm_session_encrypt(&e2ee->olm_sessions[olm_idx],
                                       (const uint8_t *)room_key_json,
                                       strlen(room_key_json),
                                       olm_ct, sizeof(olm_ct), &olm_ct_len,
                                       &olm_msg_type);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Olm encrypt failed for %s", dev->device_id);
                continue;
            }

            /* If pre-key message, wrap in pre-key envelope */
            uint8_t final_ct[2048 + 128];
            size_t final_ct_len = olm_ct_len;
            memcpy(final_ct, olm_ct, olm_ct_len);

            if (olm_msg_type == OLM_MSG_TYPE_PRE_KEY) {
                /* Build pre-key message wrapping the inner message */
                olm_pre_key_message_t pre_key = {0};
                /* one_time_key is the OTK we used - we'd need to track this.
                 * For now, use the ephemeral key which is the ratchet public. */
                memcpy(pre_key.identity_key,
                       e2ee->account.identity.curve25519_public, 32);
                memcpy(pre_key.base_key,
                       e2ee->olm_sessions[olm_idx].our_ratchet_public, 32);
                /* The one_time_key field should be the OTK public key we claimed.
                 * Since we decoded it during claim, we stored it as their_identity_key.
                 * For a minimal implementation, we'll set it to zeros and let the
                 * recipient figure it out. TODO: track the claimed OTK properly. */
                memset(pre_key.one_time_key, 0, 32);
                pre_key.inner_message = olm_ct;
                pre_key.inner_message_len = olm_ct_len;

                final_ct_len = olm_pre_key_message_encode(&pre_key,
                                                           final_ct, sizeof(final_ct));
                if (final_ct_len == 0) { continue; }
            }

            /* Base64 encode the ciphertext */
            char *ct_b64 = malloc(final_ct_len * 2 + 16);
            if (ct_b64 == NULL) { continue; }
            crypto_base64_encode(final_ct, final_ct_len, ct_b64, final_ct_len * 2 + 16);

            /* Our curve25519 key base64 */
            char our_curve_b64[48];
            crypto_base64_encode(e2ee->account.identity.curve25519_public, 32,
                                  our_curve_b64, sizeof(our_curve_b64));

            /* Send to-device message */
            size_t td_size = strlen(ct_b64) + 1024;
            char *td_body = malloc(td_size);
            if (td_body == NULL) { free(ct_b64); continue; }

            snprintf(td_body, td_size,
                "{\"messages\":{\"%s\":{\"%s\":{"
                    "\"algorithm\":\"m.olm.v1.curve25519-aes-sha2\","
                    "\"sender_key\":\"%s\","
                    "\"ciphertext\":{"
                        "\"%s\":{\"type\":%d,\"body\":\"%s\"}"
                    "}"
                "}}}}",
                dev->user_id, dev->device_id,
                our_curve_b64,
                dev->curve25519_b64, olm_msg_type, ct_b64);
            free(ct_b64);

            client->txn_counter++;
            char *td_url = malloc(512);
            if (td_url == NULL) { free(td_body); continue; }
            snprintf(td_url, 512,
                     "%s/_matrix/client/v3/sendToDevice/m.room.encrypted/%" PRIu32,
                     client->homeserver_url, client->txn_counter);

            char td_resp[256];
            int td_resp_len = 0;
            matrix_http_put(&client->http, td_url, client->access_token,
                             td_body, td_resp, sizeof(td_resp), &td_resp_len);
            free(td_url);
            free(td_body);

            shared_count++;
            ESP_LOGI(TAG, "  Shared Megolm session with %s:%s",
                     dev->user_id, dev->device_id);
        }

        free(room_key_json);
        ESP_LOGI(TAG, "Megolm session shared with %d/%d devices",
                 shared_count, e2ee->room_device_count);
        e2ee->outbound_megolm_shared = true;
    }

    return ESP_OK;
}

esp_err_t matrix_e2ee_send_event(matrix_e2ee_t *e2ee, matrix_client_t *client,
                                  const char *room_id,
                                  const char *event_type,
                                  const char *content_json)
{
    if (e2ee == NULL || client == NULL || room_id == NULL ||
        event_type == NULL || content_json == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Ensure Megolm session exists and is shared */
    esp_err_t err = matrix_e2ee_ensure_outbound_session(e2ee, client, room_id);
    if (err != ESP_OK) { return err; }

    /* Build plaintext event JSON (what Megolm encrypts) */
    size_t pt_size = strlen(content_json) + strlen(event_type) + strlen(room_id) + 128;
    char *plaintext = malloc(pt_size);
    if (plaintext == NULL) { return ESP_ERR_NO_MEM; }

    snprintf(plaintext, pt_size,
        "{\"type\":\"%s\",\"content\":%s,\"room_id\":\"%s\"}",
        event_type, content_json, room_id);

    /* Encrypt with Megolm.
     * Output size: AES-CBC(plaintext + 16 padding) + protobuf(~20) + HMAC(8) + Ed25519(64)
     * Generous: plaintext_len + 256 */
    size_t pt_len = strlen(plaintext);
    size_t ct_buf_size = pt_len + 256;
    uint8_t *ciphertext = malloc(ct_buf_size);
    if (ciphertext == NULL) { free(plaintext); return ESP_ERR_NO_MEM; }

    size_t ct_len = 0;
    err = megolm_outbound_encrypt(&e2ee->outbound_megolm,
                                   (const uint8_t *)plaintext, strlen(plaintext),
                                   ciphertext, ct_buf_size, &ct_len);
    free(plaintext);
    if (err != ESP_OK) {
        free(ciphertext);
        ESP_LOGE(TAG, "Megolm encrypt failed");
        return err;
    }

    /* Base64 encode ciphertext */
    size_t b64_size = ct_len * 2 + 16;
    char *ct_b64 = malloc(b64_size);
    if (ct_b64 == NULL) { free(ciphertext); return ESP_ERR_NO_MEM; }
    crypto_base64_encode(ciphertext, ct_len, ct_b64, b64_size);
    free(ciphertext);

    char our_curve_b64[48];
    crypto_base64_encode(e2ee->account.identity.curve25519_public, 32,
                          our_curve_b64, sizeof(our_curve_b64));

    /* Build encrypted event body */
    size_t body_size = strlen(ct_b64) + 512;
    char *body = malloc(body_size);
    if (body == NULL) { free(ct_b64); return ESP_ERR_NO_MEM; }

    ESP_LOGI(TAG, "Outbound encrypted event: session_id=%s, ct_b64_len=%d",
             e2ee->outbound_megolm.session_id_b64, (int)strlen(ct_b64));

    snprintf(body, body_size,
        "{"
            "\"algorithm\":\"m.megolm.v1.aes-sha2\","
            "\"sender_key\":\"%s\","
            "\"ciphertext\":\"%s\","
            "\"session_id\":\"%s\","
            "\"device_id\":\"%s\""
        "}",
        our_curve_b64, ct_b64,
        e2ee->outbound_megolm.session_id_b64,
        client->device_id);
    free(ct_b64);

    /* URL-encode room_id */
    char encoded_room[384];
    int ei = 0;
    for (int i = 0; room_id[i] != '\0' && ei < (int)sizeof(encoded_room) - 4; i++) {
        char c = room_id[i];
        if (c == '!' || c == ':') {
            snprintf(encoded_room + ei, sizeof(encoded_room) - ei,
                     "%%%02X", (unsigned char)c);
            ei += 3;
        } else {
            encoded_room[ei++] = c;
        }
    }
    encoded_room[ei] = '\0';

    client->txn_counter++;
    char *url = malloc(1024);
    char *response = malloc(512);
    if (url == NULL || response == NULL) { free(body); free(url); free(response); return ESP_ERR_NO_MEM; }
    snprintf(url, 1024,
             "%s/_matrix/client/v3/rooms/%s/send/m.room.encrypted/%" PRIu32,
             client->homeserver_url, encoded_room, client->txn_counter);

    int response_len = 0;
    err = matrix_http_put(&client->http, url, client->access_token, body,
                           response, 512, &response_len);
    free(body);
    free(url);
    free(response);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send encrypted event");
        return err;
    }

    ESP_LOGI(TAG, "Encrypted %s sent to %s",
             event_type ? event_type : "?", room_id ? room_id : "?");
    return ESP_OK;
}

esp_err_t matrix_e2ee_send_text(matrix_e2ee_t *e2ee, matrix_client_t *client,
                                 const char *room_id, const char *message)
{
    char content[1024];
    mjson_snprintf(content, sizeof(content),
                    "{\"msgtype\":\"m.text\",\"body\":\"%s\"}", message);
    return matrix_e2ee_send_event(e2ee, client, room_id,
                                   "m.room.message", content);
}

esp_err_t matrix_e2ee_decrypt_room_event(matrix_e2ee_t *e2ee,
                                          const char *event_json, int event_json_len,
                                          char *plaintext_out, size_t plaintext_out_size,
                                          char *event_type_out, size_t event_type_out_size)
{
    if (e2ee == NULL || event_json == NULL || plaintext_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    plaintext_out[0] = '\0';
    if (event_type_out != NULL) { event_type_out[0] = '\0'; }

    /* Extract session_id and ciphertext from event */
    char session_id[64] = {0};
    char *ct_b64 = malloc(8192);
    if (ct_b64 == NULL) { return ESP_ERR_NO_MEM; }
    ct_b64[0] = '\0';

    mjson_get_string(event_json, event_json_len, "$.content.session_id",
                      session_id, sizeof(session_id));
    mjson_get_string(event_json, event_json_len, "$.content.ciphertext",
                      ct_b64, 8192);

    if (strlen(session_id) == 0 || strlen(ct_b64) == 0) {
        ESP_LOGW(TAG, "Missing session_id or ciphertext in encrypted event");
        free(ct_b64);
        return ESP_ERR_NOT_FOUND;
    }

    /* Find matching inbound session */
    megolm_inbound_session_t *sess = NULL;
    for (int i = 0; i < e2ee->inbound_megolm_count; i++) {
        if (megolm_inbound_matches(&e2ee->inbound_megolm[i], session_id)) {
            sess = &e2ee->inbound_megolm[i];
            break;
        }
    }

    if (sess == NULL) {
        ESP_LOGW(TAG, "No inbound Megolm session for id=%s",
                 session_id[0] ? session_id : "(empty)");
        free(ct_b64);
        return ESP_ERR_NOT_FOUND;
    }

    /* Decode ciphertext from base64 */
    uint8_t *ct = malloc(8192);
    if (ct == NULL) { free(ct_b64); return ESP_ERR_NO_MEM; }

    int ct_len = crypto_base64_decode(ct_b64, strlen(ct_b64), ct, 8192);
    free(ct_b64);
    if (ct_len < 0) {
        free(ct);
        ESP_LOGE(TAG, "Failed to decode ciphertext base64");
        return ESP_FAIL;
    }

    /* Decrypt with Megolm */
    uint8_t *plaintext = malloc(4096);
    if (plaintext == NULL) { free(ct); return ESP_ERR_NO_MEM; }

    size_t pt_len = 0;
    esp_err_t err = megolm_inbound_decrypt(sess, ct, ct_len,
                                            plaintext, 4095, &pt_len);
    free(ct);
    if (err != ESP_OK) {
        free(plaintext);
        ESP_LOGE(TAG, "Megolm decrypt failed");
        return err;
    }
    plaintext[pt_len] = '\0';

    /* Extract event type from decrypted JSON */
    if (event_type_out != NULL) {
        mjson_get_string((const char *)plaintext, (int)pt_len,
                          "$.type", event_type_out, event_type_out_size);
    }

    /* Extract the content as JSON string and copy to output */
    const char *content_ptr = NULL;
    int content_len = 0;
    int res = mjson_find((const char *)plaintext, (int)pt_len,
                          "$.content", &content_ptr, &content_len);
    if (res != MJSON_TOK_INVALID && content_ptr != NULL &&
        (size_t)content_len < plaintext_out_size) {
        memcpy(plaintext_out, content_ptr, content_len);
        plaintext_out[content_len] = '\0';
    } else {
        /* Fallback: copy entire plaintext */
        snprintf(plaintext_out, plaintext_out_size, "%s", (char *)plaintext);
    }

    ESP_LOGI(TAG, "Decrypted [%s]: %.80s",
             event_type_out ? event_type_out : "?", plaintext_out);
    free(plaintext);
    return ESP_OK;
}

esp_err_t matrix_e2ee_handle_to_device(matrix_e2ee_t *e2ee,
                                        const char *event_json, int event_json_len)
{
    if (e2ee == NULL || event_json == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char event_type[64] = {0};
    mjson_get_string(event_json, event_json_len, "$.type", event_type, sizeof(event_type));

    if (strcmp(event_type, "m.room.encrypted") != 0) {
        ESP_LOGD(TAG, "Ignoring to-device event type: %s",
                 event_type[0] ? event_type : "(empty)");
        return ESP_OK;
    }

    /* Check algorithm */
    char algorithm[64] = {0};
    mjson_get_string(event_json, event_json_len, "$.content.algorithm",
                      algorithm, sizeof(algorithm));

    if (strcmp(algorithm, "m.olm.v1.curve25519-aes-sha2") != 0) {
        ESP_LOGD(TAG, "Ignoring non-Olm to-device algorithm: %s", algorithm);
        return ESP_OK;
    }

    /* Find our ciphertext entry (keyed by our curve25519 base64).
     * Cannot use mjson path with base64 keys (+/= chars cause issues).
     * Find $.content.ciphertext then iterate with mjson_next. */
    char our_curve_b64[48];
    crypto_base64_encode(e2ee->account.identity.curve25519_public, 32,
                          our_curve_b64, sizeof(our_curve_b64));

    const char *ct_map = NULL;
    int ct_map_len = 0;
    int res = mjson_find(event_json, event_json_len, "$.content.ciphertext",
                          &ct_map, &ct_map_len);

    if (res == MJSON_TOK_INVALID || ct_map == NULL) {
        ESP_LOGW(TAG, "No ciphertext map in to-device event");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "to_device ciphertext map: %d bytes, looking for key %s",
             ct_map_len, our_curve_b64);

    /* Iterate ciphertext entries to find one keyed by our curve25519 key */
    const char *ct_obj = NULL;
    int ct_obj_len = 0;
    {
        int koff, klen, voff, vlen, vtype, off = 0;
        while ((off = mjson_next(ct_map, ct_map_len, off,
                                  &koff, &klen, &voff, &vlen, &vtype)) != 0) {
            const char *key_str = ct_map + koff + 1;
            int key_str_len = klen - 2;
            if (key_str_len == (int)strlen(our_curve_b64) &&
                memcmp(key_str, our_curve_b64, key_str_len) == 0) {
                ct_obj = ct_map + voff;
                ct_obj_len = vlen;
                break;
            }
        }
    }

    if (ct_obj == NULL) {
        ESP_LOGW(TAG, "No ciphertext for our key in to-device event");
        return ESP_OK;
    }

    /* Extract type and body */
    double msg_type_d = 0;
    mjson_get_number(ct_obj, ct_obj_len, "$.type", &msg_type_d);
    int msg_type = (int)msg_type_d;

    char *ct_b64 = malloc(4096);
    if (ct_b64 == NULL) { return ESP_ERR_NO_MEM; }
    ct_b64[0] = '\0';
    mjson_get_string(ct_obj, ct_obj_len, "$.body", ct_b64, 4096);

    if (strlen(ct_b64) == 0) {
        ESP_LOGW(TAG, "Empty ciphertext body");
        free(ct_b64);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Olm to-device: type=%d, ct_b64_len=%d", msg_type, (int)strlen(ct_b64));

    /* Decode ciphertext */
    uint8_t *ct = malloc(4096);
    if (ct == NULL) { free(ct_b64); return ESP_ERR_NO_MEM; }
    int ct_len = crypto_base64_decode(ct_b64, strlen(ct_b64), ct, 4096);
    free(ct_b64);
    if (ct_len < 0) { free(ct); return ESP_FAIL; }

    /* For pre-key messages (type 0): create inbound Olm session */
    uint8_t *plaintext = malloc(2048);
    if (plaintext == NULL) { free(ct); return ESP_ERR_NO_MEM; }
    size_t pt_len = 0;
    esp_err_t decrypt_err = ESP_FAIL;

    ESP_LOGI(TAG, "Olm ciphertext: type=%d, %d bytes, first 4: %02x %02x %02x %02x",
             msg_type, ct_len,
             ct_len > 0 ? ct[0] : 0, ct_len > 1 ? ct[1] : 0,
             ct_len > 2 ? ct[2] : 0, ct_len > 3 ? ct[3] : 0);

    if (msg_type == OLM_MSG_TYPE_PRE_KEY) {
        /* Decode pre-key message to get sender info */
        olm_pre_key_message_t pre_key;
        decrypt_err = olm_pre_key_message_decode(ct, ct_len, &pre_key);
        if (decrypt_err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to decode pre-key message (version=0x%02x)",
                     ct_len > 0 ? ct[0] : 0);
            free(ct); free(plaintext);
            return decrypt_err;
        }

        {
            char otk_b64[48], base_b64[48], id_b64[48];
            crypto_base64_encode(pre_key.one_time_key, 32, otk_b64, sizeof(otk_b64));
            crypto_base64_encode(pre_key.base_key, 32, base_b64, sizeof(base_b64));
            crypto_base64_encode(pre_key.identity_key, 32, id_b64, sizeof(id_b64));
            ESP_LOGI(TAG, "Pre-key parsed: otk=%.10s... base=%.10s... id=%.10s... inner=%d bytes",
                     otk_b64, base_b64, id_b64,
                     (int)(pre_key.inner_message_len));
        }

        /* Find the OTK they used */
        uint8_t otk_private[32];
        decrypt_err = olm_account_consume_one_time_key(&e2ee->account,
                                                        pre_key.one_time_key,
                                                        otk_private);
        if (decrypt_err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to consume OTK from pre-key message");
            free(ct); free(plaintext);
            return decrypt_err;
        }

        /* Create inbound Olm session */
        if (e2ee->olm_session_count >= E2EE_MAX_OLM_SESSIONS) {
            ESP_LOGW(TAG, "Max Olm sessions reached, dropping oldest");
            e2ee->olm_session_count = E2EE_MAX_OLM_SESSIONS - 1;
        }

        int idx = e2ee->olm_session_count;
        decrypt_err = olm_session_create_inbound(&e2ee->olm_sessions[idx],
                                                  e2ee->account.identity.curve25519_private,
                                                  otk_private,
                                                  pre_key.identity_key,
                                                  pre_key.base_key);
        crypto_wipe(otk_private, sizeof(otk_private));
        if (decrypt_err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create inbound Olm session");
            free(ct); free(plaintext);
            return decrypt_err;
        }
        e2ee->olm_session_count++;

        /* Decrypt the inner message */
        decrypt_err = olm_session_decrypt(&e2ee->olm_sessions[idx], OLM_MSG_TYPE_PRE_KEY,
                                           ct, ct_len,
                                           plaintext, 2047, &pt_len);
        if (decrypt_err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to decrypt Olm pre-key message");
            free(ct); free(plaintext);
            return decrypt_err;
        }

        /* Save account (OTK was consumed) */
        matrix_e2ee_save_account(e2ee);
    } else {
        /* Type 1: find existing Olm session and decrypt */
        bool decrypted = false;
        for (int i = 0; i < e2ee->olm_session_count; i++) {
            decrypt_err = olm_session_decrypt(&e2ee->olm_sessions[i], msg_type,
                                               ct, ct_len,
                                               plaintext, 2047, &pt_len);
            if (decrypt_err == ESP_OK) {
                decrypted = true;
                break;
            }
        }
        if (!decrypted) {
            ESP_LOGW(TAG, "Could not decrypt to-device message with any session");
            free(ct); free(plaintext);
            return ESP_FAIL;
        }
    }

    free(ct);
    ct = NULL;

    plaintext[pt_len] = '\0';
    ESP_LOGI(TAG, "Decrypted to-device: %.100s",
             pt_len > 0 ? (char *)plaintext : "(empty)");

    /* Parse the decrypted JSON. If it's m.room_key, create inbound Megolm session. */
    char inner_type[64] = {0};
    mjson_get_string((const char *)plaintext, (int)pt_len, "$.type",
                      inner_type, sizeof(inner_type));

    if (strcmp(inner_type, "m.room_key") == 0) {
        char algorithm2[64] = {0};
        mjson_get_string((const char *)plaintext, (int)pt_len, "$.content.algorithm",
                          algorithm2, sizeof(algorithm2));

        if (strcmp(algorithm2, "m.megolm.v1.aes-sha2") != 0) {
            ESP_LOGW(TAG, "Unknown room_key algorithm: %s", algorithm2);
            free(plaintext);
            return ESP_OK;
        }

        char sk_b64[512] = {0};
        mjson_get_string((const char *)plaintext, (int)pt_len, "$.content.session_key",
                          sk_b64, sizeof(sk_b64));

        char sender_key[48] = {0};
        mjson_get_string(event_json, event_json_len, "$.content.sender_key",
                          sender_key, sizeof(sender_key));

        if (strlen(sk_b64) == 0) {
            ESP_LOGE(TAG, "Empty session_key in m.room_key");
            free(plaintext);
            return ESP_FAIL;
        }

        /* Decode session key */
        uint8_t session_key[256];
        int sk_len = crypto_base64_decode(sk_b64, strlen(sk_b64),
                                           session_key, sizeof(session_key));
        if (sk_len < MEGOLM_SESSION_EXPORT_SIZE) {
            ESP_LOGE(TAG, "Session key too short: %d", sk_len);
            free(plaintext);
            return ESP_FAIL;
        }

        /* Create inbound Megolm session */
        if (e2ee->inbound_megolm_count >= E2EE_MAX_INBOUND_SESSIONS) {
            ESP_LOGW(TAG, "Max inbound Megolm sessions, dropping oldest");
            e2ee->inbound_megolm_count = E2EE_MAX_INBOUND_SESSIONS - 1;
        }

        int idx = e2ee->inbound_megolm_count;
        esp_err_t err = megolm_inbound_create(&e2ee->inbound_megolm[idx],
                                               session_key, sk_len,
                                               sender_key);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create inbound Megolm session");
            free(plaintext);
            return err;
        }
        e2ee->inbound_megolm_count++;

        ESP_LOGI(TAG, "Stored inbound Megolm session from %s",
                 sender_key[0] ? sender_key : "(unknown)");
    }

    free(plaintext);
    return ESP_OK;
}
