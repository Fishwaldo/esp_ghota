#include <stdlib.h>
#include <fnmatch.h>
#include <libgen.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_http_client.h>
#include <esp_tls.h>
#include <esp_crt_bundle.h>
#include <esp_log.h>
#include <esp_app_format.h>
#include <esp_ota_ops.h>
#include <esp_https_ota.h>
#include <esp_event.h>

#include <sdkconfig.h>
#include "esp_ghota.h"
#include "lwjson.h"

static const char *TAG = "GHOTA";

ESP_EVENT_DEFINE_BASE(GHOTA_EVENTS);

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
#define PRICONTENT_LENGTH PRId64
#else
#define PRICONTENT_LENGTH PRId32
#endif
typedef struct ghota_client_handle_t
{
    ghota_config_t config;
    char *username;
    char *token;
    struct
    {
        char tag_name[CONFIG_MAX_FILENAME_LEN];
        char name[CONFIG_MAX_FILENAME_LEN];
        char url[CONFIG_MAX_URL_LEN];
        char storageurl[CONFIG_MAX_URL_LEN];
        uint8_t flags;
    } result;
    struct
    {
        char name[CONFIG_MAX_FILENAME_LEN];
        char url[CONFIG_MAX_URL_LEN];
    } scratch;
    semver_t current_version;
    semver_t latest_version;
    uint32_t countdown;
    TaskHandle_t task_handle;
    const esp_partition_t *storage_partition;
} ghota_client_handle_t;

enum release_flags
{
    GHOTA_RELEASE_GOT_TAG = 0x01,
    GHOTA_RELEASE_GOT_FNAME = 0x02,
    GHOTA_RELEASE_GOT_URL = 0x04,
    GHOTA_RELEASE_GOT_STORAGE = 0x08,
    GHOTA_RELEASE_VALID_ASSET = 0x10,
} release_flags;

SemaphoreHandle_t ghota_lock = NULL;

static void SetFlag(ghota_client_handle_t *handle, enum release_flags flag)
{
    handle->result.flags |= flag;
}
static bool GetFlag(ghota_client_handle_t *handle, enum release_flags flag)
{
    return handle->result.flags & flag;
}

static void ClearFlag(ghota_client_handle_t *handle, enum release_flags flag)
{
    handle->result.flags &= ~flag;
}

ghota_client_handle_t *ghota_init(ghota_config_t *newconfig)
{
    if (!ghota_lock)
    {
        ghota_lock = xSemaphoreCreateMutex();
    }
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return NULL;
    }
    ghota_client_handle_t *handle = malloc(sizeof(ghota_client_handle_t));
    if (handle == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for client handle");
        xSemaphoreGive(ghota_lock);
        return NULL;
    }
    bzero(handle, sizeof(ghota_client_handle_t));
    strncpy(handle->config.filenamematch, newconfig->filenamematch, CONFIG_MAX_FILENAME_LEN);
    strncpy(handle->config.storagenamematch, newconfig->storagenamematch, CONFIG_MAX_FILENAME_LEN);
    strncpy(handle->config.storagepartitionname, newconfig->storagepartitionname, 17);
    if (newconfig->hostname == NULL)
        asprintf(&handle->config.hostname, CONFIG_GITHUB_HOSTNAME);
    else
        asprintf(&handle->config.hostname, newconfig->hostname);

    if (newconfig->orgname == NULL)
        asprintf(&handle->config.orgname, CONFIG_GITHUB_OWNER);
    else
        asprintf(&handle->config.orgname, newconfig->orgname);

    if (newconfig->reponame == NULL)
        asprintf(&handle->config.reponame, CONFIG_GITHUB_REPO);
    else
        asprintf(&handle->config.reponame, newconfig->reponame);
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    const esp_app_desc_t *app_desc = esp_app_get_description();
#else
    const esp_app_desc_t *app_desc = esp_ota_get_app_description();
#endif
    if (semver_parse(app_desc->version, &handle->current_version))
    {
        ESP_LOGE(TAG, "Failed to parse current version");
        ghota_free(handle);
        xSemaphoreGive(ghota_lock);
        return NULL;
    }
    handle->result.flags = 0;

    //    if (newconfig->updateInterval < 60) {
    //        ESP_LOGE(TAG, "Update interval must be at least 60 Minutes");
    //        newconfig->updateInterval = 60;
    //    }
    handle->config.updateInterval = newconfig->updateInterval;

    handle->task_handle = NULL;
    xSemaphoreGive(ghota_lock);

    return handle;
}

esp_err_t ghota_free(ghota_client_handle_t *handle)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    free(handle->config.hostname);
    free(handle->config.orgname);
    free(handle->config.reponame);
    if (handle->username)
        free(handle->username);
    if (handle->token)
        free(handle->token);
    semver_free(&handle->current_version);
    semver_free(&handle->latest_version);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

esp_err_t ghota_set_auth(ghota_client_handle_t *handle, const char *username, const char *password)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    asprintf(&handle->username, "%s", username);
    asprintf(&handle->token, "%s", password);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

static void lwjson_callback(lwjson_stream_parser_t *jsp, lwjson_stream_type_t type)
{
    if (jsp->udata == NULL)
    {
        ESP_LOGE(TAG, "No user data for callback");
        return;
    }
    ghota_client_handle_t *handle = (ghota_client_handle_t *)jsp->udata;
#ifdef DEBUG
    ESP_LOGI(TAG, "Lwjson Called: %d %d %d %d", jsp->stack_pos, jsp->stack[jsp->stack_pos - 1].type, type, handle->result.flags);
    if (jsp->stack[jsp->stack_pos - 1].type == LWJSON_STREAM_TYPE_KEY)
    { /* We need key to be before */
        ESP_LOGI(TAG, "Key: %s", jsp->stack[jsp->stack_pos - 1].meta.name);
    }
#endif
    /* Get a value corresponsing to "tag_name" key */
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_TAG))
    {
        if (jsp->stack_pos >= 2                                /* Number of stack entries must be high */
            && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT /* First must be object */
            && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY    /* We need key to be before */
            && strcasecmp(jsp->stack[1].meta.name, "tag_name") == 0)
        {
            ESP_LOGD(TAG, "Got '%s' with value '%s'", jsp->stack[1].meta.name, jsp->data.str.buff);
            strncpy(handle->result.tag_name, jsp->data.str.buff, CONFIG_MAX_FILENAME_LEN);
            SetFlag(handle, GHOTA_RELEASE_GOT_TAG);
        }
    }
    if (!GetFlag(handle, GHOTA_RELEASE_VALID_ASSET) || !GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE))
    {
        if (jsp->stack_pos == 5 && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY && strcasecmp(jsp->stack[1].meta.name, "assets") == 0 && jsp->stack[2].type == LWJSON_STREAM_TYPE_ARRAY && jsp->stack[3].type == LWJSON_STREAM_TYPE_OBJECT && jsp->stack[4].type == LWJSON_STREAM_TYPE_KEY)
        {
            ESP_LOGD(TAG, "Assets Got key '%s' with value '%s'", jsp->stack[jsp->stack_pos - 1].meta.name, jsp->data.str.buff);
            if (strcasecmp(jsp->stack[4].meta.name, "name") == 0)
            {
                strncpy(handle->scratch.name, jsp->data.str.buff, CONFIG_MAX_FILENAME_LEN);
                SetFlag(handle, GHOTA_RELEASE_GOT_FNAME);
                ESP_LOGD(TAG, "Got Filename for Asset: %s", handle->scratch.name);
            }
            if (strcasecmp(jsp->stack[4].meta.name, "url") == 0)
            {
                strncpy(handle->scratch.url, jsp->data.str.buff, CONFIG_MAX_URL_LEN);
                SetFlag(handle, GHOTA_RELEASE_GOT_URL);
                ESP_LOGD(TAG, "Got URL for Asset: %s", handle->scratch.url);
            }
            /* Now test if we got both name an download url */
            if (GetFlag(handle, GHOTA_RELEASE_GOT_FNAME) && GetFlag(handle, GHOTA_RELEASE_GOT_URL))
            {
                ESP_LOGD(TAG, "Testing Firmware filenames %s -> %s - Matching Filename against %s and %s", handle->scratch.name, handle->scratch.url, handle->config.filenamematch, handle->config.storagenamematch);
                /* see if the filename matches */
                if (!GetFlag(handle, GHOTA_RELEASE_VALID_ASSET) && fnmatch(handle->config.filenamematch, handle->scratch.name, 0) == 0)
                {
                    strncpy(handle->result.name, handle->scratch.name, CONFIG_MAX_FILENAME_LEN);
                    strncpy(handle->result.url, handle->scratch.url, CONFIG_MAX_URL_LEN);
                    ESP_LOGD(TAG, "Valid Firmware Found: %s - %s", handle->result.name, handle->result.url);
                    SetFlag(handle, GHOTA_RELEASE_VALID_ASSET);
                }
                else if (!GetFlag(handle, GHOTA_RELEASE_GOT_STORAGE) && fnmatch(handle->config.storagenamematch, handle->scratch.name, 0) == 0)
                {
                    strncpy(handle->result.storageurl, handle->scratch.url, CONFIG_MAX_URL_LEN);
                    ESP_LOGD(TAG, "Valid Storage Asset Found: %s - %s", handle->scratch.name, handle->result.storageurl);
                    SetFlag(handle, GHOTA_RELEASE_GOT_STORAGE);
                }
                else
                {
                    ESP_LOGD(TAG, "Invalid Asset Found: %s", handle->scratch.name);
                    ClearFlag(handle, GHOTA_RELEASE_GOT_FNAME);
                    ClearFlag(handle, GHOTA_RELEASE_GOT_URL);
                }
            }
        }
    }
}

static esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    lwjsonr_t res;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_HEADER:
        if (strncasecmp(evt->header_key, "x-ratelimit-remaining", strlen("x-ratelimit-remaining")) == 0)
        {
            int limit = atoi(evt->header_value);
            ESP_LOGD(TAG, "Github API Rate Limit Remaining: %d", limit);
            if (limit < 10)
            {
                ESP_LOGW(TAG, "Github API Rate Limit Remaining is low: %d", limit);
            }
        }
        break;
    case HTTP_EVENT_ON_DATA:
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            char *buf = evt->data;
            for (int i = 0; i < evt->data_len; i++)
            {
                res = lwjson_stream_parse((lwjson_stream_parser_t *)evt->user_data, *buf);
                if (!(res == lwjsonOK || res == lwjsonSTREAMDONE || res == lwjsonSTREAMINPROG))
                {
                    ESP_LOGE(TAG, "Lwjson Error: %d", res);
                }
                buf++;
            }
        }
        break;
    case HTTP_EVENT_DISCONNECTED:
    {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        break;
    }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t ghota_check(ghota_client_handle_t *handle)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to get lock");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Checking for new release");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_CHECK, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
    lwjson_stream_parser_t stream_parser;
    lwjsonr_t res;

    res = lwjson_stream_init(&stream_parser, lwjson_callback);
    if (res != lwjsonOK)
    {
        ESP_LOGE(TAG, "Failed to initialize JSON parser: %d", res);
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    stream_parser.udata = (void *)handle;

    char url[CONFIG_MAX_URL_LEN];
    snprintf(url, CONFIG_MAX_URL_LEN, "https://%s/repos/%s/%s/releases/latest", handle->config.hostname, handle->config.orgname, handle->config.reponame);

    esp_http_client_config_t httpconfig = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = _http_event_handler,
        .user_data = &stream_parser,
    };
    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", url);
        httpconfig.username = handle->username;
        httpconfig.password = handle->token;
        httpconfig.auth_type = HTTP_AUTH_TYPE_BASIC;
    }
    ESP_LOGI(TAG, "Searching for Firmware from %s", url);

    esp_http_client_handle_t client = esp_http_client_init(&httpconfig);

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRICONTENT_LENGTH ,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    if (esp_http_client_get_status_code(client) == 200)
    {
        if (GetFlag(handle, GHOTA_RELEASE_VALID_ASSET))
        {
            if (semver_parse(handle->result.tag_name, &handle->latest_version))
            {
                ESP_LOGE(TAG, "Failed to parse new version");
                esp_http_client_cleanup(client);
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
                xSemaphoreGive(ghota_lock);
                return ESP_FAIL;
            }
            ESP_LOGI(TAG, "Current Version %d.%d.%d", handle->current_version.major, handle->current_version.minor, handle->current_version.patch);
            ESP_LOGI(TAG, "New Version %d.%d.%d", handle->latest_version.major, handle->latest_version.minor, handle->latest_version.patch);
            ESP_LOGI(TAG, "Asset: %s", handle->result.name);
            ESP_LOGI(TAG, "Firmware URL: %s", handle->result.url);
            if (strlen(handle->result.storageurl))
            {
                ESP_LOGI(TAG, "Storage URL: %s", handle->result.storageurl);
            }
        }
        else
        {
            ESP_LOGI(TAG, "Asset: No Valid Firmware Assets Found");
            esp_http_client_cleanup(client);
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
            xSemaphoreGive(ghota_lock);
            return ESP_FAIL;
        }
    }
    else
    {
        ESP_LOGW(TAG, "Github Release API Returned: %d", esp_http_client_get_status_code(client));
        esp_http_client_cleanup(client);
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    esp_http_client_cleanup(client);
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

static esp_err_t validate_image_header(esp_app_desc_t *new_app_info)
{
    if (new_app_info == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "New Firmware Details:");
    ESP_LOGI(TAG, "Project name: %s", new_app_info->project_name);
    ESP_LOGI(TAG, "Firmware version: %s", new_app_info->version);
    ESP_LOGI(TAG, "Compiled time: %s %s", new_app_info->date, new_app_info->time);
    ESP_LOGI(TAG, "ESP-IDF: %s", new_app_info->idf_ver);
    ESP_LOGI(TAG, "SHA256:");
    ESP_LOG_BUFFER_HEX(TAG, new_app_info->app_elf_sha256, sizeof(new_app_info->app_elf_sha256));

    const esp_partition_t *running = esp_ota_get_running_partition();
    ESP_LOGD(TAG, "Current partition %s type %d subtype %d (offset 0x%08" PRIx32 ")",
             running->label, running->type, running->subtype, running->address);
    const esp_partition_t *update = esp_ota_get_next_update_partition(NULL);
    ESP_LOGD(TAG, "Update partition %s type %d subtype %d (offset 0x%08" PRIx32 ")",
             update->label, update->type, update->subtype, update->address);

#ifdef CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    /**
     * Secure version check from firmware image header prevents subsequent download and flash write of
     * entire firmware image. However this is optional because it is also taken care in API
     * esp_https_ota_finish at the end of OTA update procedure.
     */
    const uint32_t hw_sec_version = esp_efuse_read_secure_version();
    if (new_app_info->secure_version < hw_sec_version)
    {
        ESP_LOGW(TAG, "New firmware security version is less than eFuse programmed, %d < %d", new_app_info->secure_version, hw_sec_version);
        return ESP_FAIL;
    }
#endif

    return ESP_OK;
}

static esp_err_t http_client_set_header_cb(esp_http_client_handle_t http_client)
{
    return esp_http_client_set_header(http_client, "Accept", "application/octet-stream");
}

esp_err_t _http_event_storage_handler(esp_http_client_event_t *evt)
{
    static int output_pos;
    static int last_progress;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_CONNECTED:
    {
        output_pos = 0;
        last_progress = 0;
        /* Erase the Partition */
        break;
    }
    case HTTP_EVENT_ON_DATA:
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            ghota_client_handle_t *handle = (ghota_client_handle_t *)evt->user_data;
            if (output_pos == 0)
            {
                ESP_LOGD(TAG, "Erasing Partition");
                ESP_ERROR_CHECK(esp_partition_erase_range(handle->storage_partition, 0, handle->storage_partition->size));
                ESP_LOGD(TAG, "Erasing Complete");
            }

            ESP_ERROR_CHECK(esp_partition_write(handle->storage_partition, output_pos, evt->data, evt->data_len));
            output_pos += evt->data_len;
            int progress = 100 * ((float)output_pos / (float)handle->storage_partition->size);
            if ((progress % 5 == 0) && (progress != last_progress))
            {
                ESP_LOGV(TAG, "Storage Firmware Update Progress: %d%%", progress);
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_STORAGE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
                last_progress = progress;
            }
        }
        break;
    case HTTP_EVENT_DISCONNECTED:
    {
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        break;
    }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t ghota_storage_update(ghota_client_handle_t *handle)
{
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    if (handle == NULL)
    {
        ESP_LOGE(TAG, "Invalid Handle");
        xSemaphoreGive(ghota_lock);
        return ESP_ERR_INVALID_ARG;
    }
    if (!strlen(handle->result.storageurl))
    {
        ESP_LOGE(TAG, "No Storage URL");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    if (!strlen(handle->config.storagepartitionname))
    {
        ESP_LOGE(TAG, "No Storage Partition Name");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    handle->storage_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, handle->config.storagepartitionname);
    if (handle->storage_partition == NULL)
    {
        ESP_LOGE(TAG, "Storage Partition Not Found");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, "Storage Partition %s - Type %x Subtype %x Found at %" PRIx32 " - size %" PRIu32, handle->storage_partition->label, handle->storage_partition->type, handle->storage_partition->subtype, handle->storage_partition->address, handle->storage_partition->size);
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_STORAGE_UPDATE, NULL, 0, portMAX_DELAY));
    /* give time for the system to react, such as unmounting the filesystems etc */
    vTaskDelay(pdMS_TO_TICKS(1000));

    esp_http_client_config_t config = {
        .url = handle->result.storageurl,
        .event_handler = _http_event_storage_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .user_data = handle,
        .buffer_size_tx = 2048,

    };
    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", config.url);
        config.username = handle->username;
        config.password = handle->token;
        config.auth_type = HTTP_AUTH_TYPE_BASIC;
    }
    esp_http_client_handle_t client = esp_http_client_init(&config);
    ESP_ERROR_CHECK(esp_http_client_set_header(client, "Accept", "application/octet-stream"));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRICONTENT_LENGTH,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
        uint8_t sha256[32] = {0};
        ESP_ERROR_CHECK(esp_partition_get_sha256(handle->storage_partition, sha256));
        ESP_LOG_BUFFER_HEX("New Storage Partition SHA256:", sha256, sizeof(sha256));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_STORAGE_UPDATE, NULL, 0, portMAX_DELAY));
    }
    else
    {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_STORAGE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    }
    esp_http_client_cleanup(client);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

esp_err_t ghota_update(ghota_client_handle_t *handle)
{
    esp_err_t ota_finish_err = ESP_OK;
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Scheduled Check for Firmware Update Starting");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_UPDATE, NULL, 0, portMAX_DELAY));
    if (!GetFlag(handle, GHOTA_RELEASE_VALID_ASSET))
    {
        ESP_LOGE(TAG, "No Valid Release Asset Found");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    int cmp = semver_compare_version(handle->latest_version, handle->current_version);
    if (cmp != 1)
    {
        ESP_LOGE(TAG, "Current Version is equal or newer than new release");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_OK;
    }
    esp_http_client_config_t httpconfig = {
        .url = handle->result.url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
        .buffer_size_tx = 4096,
    };

    if (handle->username)
    {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", httpconfig.url);
        httpconfig.username = handle->username;
        httpconfig.password = handle->token;
        httpconfig.auth_type = HTTP_AUTH_TYPE_BASIC;
    }

    esp_https_ota_config_t ota_config = {
        .http_config = &httpconfig,
        .http_client_init_cb = http_client_set_header_cb,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ESP HTTPS OTA Begin failed: %d", err);
        goto ota_end;
    }

    esp_app_desc_t app_desc;
    err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_https_ota_read_img_desc failed: %d", err);
        goto ota_end;
    }
    err = validate_image_header(&app_desc);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "image header verification failed: %d", err);
        goto ota_end;
    }
    int last_progress = -1;
    while (1)
    {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS)
        {
            break;
        }
        int32_t dl = esp_https_ota_get_image_len_read(https_ota_handle);
        int32_t size = esp_https_ota_get_image_size(https_ota_handle);
        int progress = 100 * ((float)dl / (float)size);
        if ((progress % 5 == 0) && (progress != last_progress))
        {
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
            ESP_LOGV(TAG, "Firmware Update Progress: %d%%", progress);
            last_progress = progress;
        }
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true)
    {
        // the OTA image was not completely received and user can customise the response to this situation.
        ESP_LOGE(TAG, "Complete data was not received.");
    }
    else
    {
        ota_finish_err = esp_https_ota_finish(https_ota_handle);
        if ((err == ESP_OK) && (ota_finish_err == ESP_OK))
        {
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_UPDATE, NULL, 0, portMAX_DELAY));
            if (strlen(handle->result.storageurl))
            {
                xSemaphoreGive(ghota_lock);
                if (ghota_storage_update(handle) == ESP_OK)
                {
                    ESP_LOGI(TAG, "Storage Update Successful");
                }
                else
                {
                    ESP_LOGE(TAG, "Storage Update Failed");
                }
            }
            else
            {
                xSemaphoreGive(ghota_lock);
            }
            ESP_LOGI(TAG, "ESP_HTTPS_OTA upgrade successful. Rebooting ...");
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_PENDING_REBOOT, NULL, 0, portMAX_DELAY));
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            esp_restart();
            return ESP_OK;
        }
        else
        {
            if (ota_finish_err == ESP_ERR_OTA_VALIDATE_FAILED)
            {
                ESP_LOGE(TAG, "Image validation failed, image is corrupted");
            }
            ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed 0x%x", ota_finish_err);
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
            xSemaphoreGive(ghota_lock);
            return ESP_FAIL;
        }
    }

ota_end:
    esp_https_ota_abort(https_ota_handle);
    ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    xSemaphoreGive(ghota_lock);
    return ESP_FAIL;
}

semver_t *ghota_get_current_version(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        return NULL;
    }
    semver_t *cur = malloc(sizeof(semver_t));
    memcpy(cur, &handle->current_version, sizeof(semver_t));
    return cur;
}

semver_t *ghota_get_latest_version(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        return NULL;
    }
    if (!GetFlag(handle, GHOTA_RELEASE_VALID_ASSET))
    {
        return NULL;
    }
    semver_t *new = malloc(sizeof(semver_t));
    memcpy(new, &handle->latest_version, sizeof(semver_t));
    return new;
}

static void ghota_task(void *pvParameters)
{
    ghota_client_handle_t *handle = (ghota_client_handle_t *)pvParameters;
    ESP_LOGI(TAG, "Firmware Update Task Starting");
    if (handle)
    {
        if (ghota_check(handle) == ESP_OK)
        {
            if (semver_gt(handle->latest_version, handle->current_version) == 1)
            {
                ESP_LOGI(TAG, "New Version Available");
                ghota_update(handle);
            }
            else
            {
                ESP_LOGI(TAG, "No New Version Available");
                ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, NULL, 0, portMAX_DELAY));
            }
        }
        else
        {
            ESP_LOGI(TAG, "No Update Available");
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NOUPDATE_AVAILABLE, NULL, 0, portMAX_DELAY));
        }
    }
    ESP_LOGI(TAG, "Firmware Update Task Finished");
    vTaskDelete(handle->task_handle);
    vTaskDelay(pdMS_TO_TICKS(1000));
    handle->task_handle = NULL;
}

esp_err_t ghota_start_update_task(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        return ESP_FAIL;
    }
    eTaskState state = eInvalid;
    TaskHandle_t tmp = xTaskGetHandle("ghota_task");
    if (tmp)
    {
        state = eTaskGetState(tmp);
    }
    if (state == eDeleted || state == eInvalid)
    {
        ESP_LOGD(TAG, "Starting Task to Check for Updates");
        if (xTaskCreate(ghota_task, "ghota_task", 6144, handle, 5, &handle->task_handle) != pdPASS)
        {
            ESP_LOGW(TAG, "Failed to Start ghota_task");
            return ESP_FAIL;
        }
    }
    else
    {
        ESP_LOGW(TAG, "ghota_task Already Running");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void ghota_timer_callback(TimerHandle_t xTimer)
{
    ghota_client_handle_t *handle = (ghota_client_handle_t *)pvTimerGetTimerID(xTimer);
    if (handle)
    {
        handle->countdown--;
        if (handle->countdown == 0)
        {
            handle->countdown = handle->config.updateInterval;
            ghota_start_update_task(handle);
        }
    }
}

esp_err_t ghota_start_update_timer(ghota_client_handle_t *handle)
{
    if (!handle)
    {
        ESP_LOGE(TAG, "Failed to initialize GHOTA Client");
        return ESP_FAIL;
    }
    handle->countdown = handle->config.updateInterval;

    /* run timer every minute */
    uint64_t ticks = pdMS_TO_TICKS(1000) * 60;
    TimerHandle_t timer = xTimerCreate("ghota_timer", ticks, pdTRUE, (void *)handle, ghota_timer_callback);
    if (timer == NULL)
    {
        ESP_LOGE(TAG, "Failed to create timer");
        return ESP_FAIL;
    }
    else
    {
        if (xTimerStart(timer, 0) != pdPASS)
        {
            ESP_LOGE(TAG, "Failed to start timer");
            return ESP_FAIL;
        }
        else
        {
            ESP_LOGI(TAG, "Started Update Timer for %" PRIu32 " Minutes", handle->config.updateInterval);
        }
    }
    return ESP_OK;
}

char *ghota_get_event_str(ghota_event_e event)
{
    switch (event)
    {
    case GHOTA_EVENT_START_CHECK:
        return "GHOTA_EVENT_START_CHECK";
    case GHOTA_EVENT_UPDATE_AVAILABLE:
        return "GHOTA_EVENT_UPDATE_AVAILABLE";
    case GHOTA_EVENT_NOUPDATE_AVAILABLE:
        return "GHOTA_EVENT_NOUPDATE_AVAILABLE";
    case GHOTA_EVENT_START_UPDATE:
        return "GHOTA_EVENT_START_UPDATE";
    case GHOTA_EVENT_FINISH_UPDATE:
        return "GHOTA_EVENT_FINISH_UPDATE";
    case GHOTA_EVENT_UPDATE_FAILED:
        return "GHOTA_EVENT_UPDATE_FAILED";
    case GHOTA_EVENT_START_STORAGE_UPDATE:
        return "GHOTA_EVENT_START_STORAGE_UPDATE";
    case GHOTA_EVENT_FINISH_STORAGE_UPDATE:
        return "GHOTA_EVENT_FINISH_STORAGE_UPDATE";
    case GHOTA_EVENT_STORAGE_UPDATE_FAILED:
        return "GHOTA_EVENT_STORAGE_UPDATE_FAILED";
    case GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS:
        return "GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS";
    case GHOTA_EVENT_STORAGE_UPDATE_PROGRESS:
        return "GHOTA_EVENT_STORAGE_UPDATE_PROGRESS";
    case GHOTA_EVENT_PENDING_REBOOT:
        return "GHOTA_EVENT_PENDING_REBOOT";
    }
    return "Unknown Event";
}