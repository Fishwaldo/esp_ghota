#ifndef GITHUB_OTA_H
#define GITHUB_OTA_H

#include <esp_err.h>
#include <esp_event.h>
#include "semver.h"

#ifdef __cplusplus
extern "C" {
#endif

ESP_EVENT_DECLARE_BASE(GHOTA_EVENTS);

/** 
 * @brief Github OTA events
 * These events are posted to the event loop to track progress of the OTA process
 */
typedef enum
{
    GHOTA_EVENT_START_CHECK = 0x01,    /*!< Github OTA check started */
    GHOTA_EVENT_UPDATE_AVAILABLE = 0x02,   /*!< Github OTA update available */
    GHOTA_EVENT_NOUPDATE_AVAILABLE = 0x04, /*!< Github OTA no update available */
    GHOTA_EVENT_START_UPDATE = 0x08,  /*!< Github OTA update started */
    GHOTA_EVENT_FINISH_UPDATE = 0x10, /*!< Github OTA update finished */
    GHOTA_EVENT_UPDATE_FAILED = 0x20, /*!< Github OTA update failed */
    GHOTA_EVENT_START_STORAGE_UPDATE = 0x40, /*!< Github OTA storage update started. If the storage is mounted, you should unmount it when getting this call */
    GHOTA_EVENT_FINISH_STORAGE_UPDATE = 0x80, /*!< Github OTA storage update finished. You can mount the new storage after getting this call if needed */
    GHOTA_EVENT_STORAGE_UPDATE_FAILED = 0x100, /*!< Github OTA storage update failed */
    GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS = 0x200, /*!< Github OTA firmware update progress */
    GHOTA_EVENT_STORAGE_UPDATE_PROGRESS = 0x400, /*!< Github OTA storage update progress */
    GHOTA_EVENT_PENDING_REBOOT = 0x800, /*!< Github OTA pending reboot */
} ghota_event_e;

/**
 * @brief Github OTA Configuration
 */
typedef struct ghota_config_t {
    char filenamematch[CONFIG_MAX_FILENAME_LEN]; /*!< Filename to match against on Github indicating this is a firmware file */
    char storagenamematch[CONFIG_MAX_FILENAME_LEN]; /*!< Filename to match against on Github indicating this is a storage file */
    char storagepartitionname[17]; /*!< Name of the storage partition to update */
    char *hostname; /*!< Hostname of the Github server. Defaults to api.github.com*/
    char *orgname; /*!< Name of the Github organization */
    char *reponame; /*!< Name of the Github repository */
    uint32_t updateInterval; /*!< Interval in Minutes to check for updates if using the ghota_start_update_timer function */
} ghota_config_t;

typedef struct ghota_client_handle_t ghota_client_handle_t;

/**
 * @brief  Initialize the github ota client
 * 
 * 
 * @param config [in] Configuration for the github ota client
 * @return ghota_client_handle_t* handle to pass to all subsequent calls. If it returns NULL, there is a error in your config
 */
ghota_client_handle_t *ghota_init(ghota_config_t *config);

/**
 * @brief Set the Username and Password to access private repositories or get more API calls
 * 
 * Anonymus API calls are limited to 60 per hour. If you want to get more calls, you need to set a username and password.
 * Be aware that this will be stored in the flash and can be read by anyone with access to the flash.
 * The password should be a Github Personal Access Token and for good security you should limit what it can do
 * 
 * @param handle the handle returned by ghota_init
 * @param username the username to authenticate with
 * @param password this Github Personal Access Token
 * @return esp_err_t ESP_OK if all is good, ESP_FAIL if there is an error
 */
esp_err_t ghota_set_auth(ghota_client_handle_t *handle, const char *username, const char *password);
/**
 * @brief Free the ghota client handle and all resources
 * 
 * @param handle the Handle
 * @return esp_err_t if there was a error
 */
esp_err_t ghota_free(ghota_client_handle_t *handle);

/**
 * @brief Perform a check for updates
 * 
 * This will just check if there is a available update on Github releases with download resources that match your configuration
 * for firmware and storage files. If it returns ESP_OK, you can call ghota_get_latest_version to get the version of the latest release
 * 
 * @param handle the ghota_client_handle_t handle
 * @return esp_err_t ESP_OK if there is a update available, ESP_FAIL if there is no update available or an error
 */
esp_err_t ghota_check(ghota_client_handle_t *handle);

/**
 * @brief Downloads and writes the latest firmware and storage partition (if available)
 * 
 * You should only call this after calling ghota_check and ensuring that there is a update available. 
 * 
 * @param handle the ghota_client_handle_t handle
 * @return esp_err_t ESP_FAIL if there is a error. If the Update is successful, it will not return, but reboot the device
 */
esp_err_t ghota_update(ghota_client_handle_t *handle);

/**
 * @brief Get the currently running version of the firmware
 * 
 * This will return the version of the firmware currently running on your device. 
 * consult semver.h for functions to compare versions
 * 
 * @param handle the ghota_client_handle_t handle
 * @return semver_t the version of the latest release
 */

semver_t *ghota_get_current_version(ghota_client_handle_t *handle);

/**
 * @brief Get the version of the latest release on Github. Only valid after calling ghota_check
 * 
 * @param handle the ghota_client_handle_t handle
 * @return semver_t* the version of the latest release on Github
 */
semver_t *ghota_get_latest_version(ghota_client_handle_t *handle);

/**
 * @brief Start a new Task that will check for updates and update if available
 * 
 * This is equivalent to calling ghota_check and ghota_update if there is a new update available.
 * If no update is available, it will not update the device.
 * 
 * Progress can be monitored by registering for the GHOTA_EVENTS events on the Global Event Loop
 * 
 * @param handle ghota_client_handle_t handle
 * @return esp_err_t ESP_OK if the task was started, ESP_FAIL if there was an error
 */
esp_err_t ghota_start_update_task(ghota_client_handle_t *handle);

/**
 * @brief Install a Timer to automatically check for new updates and update if available
 * 
 * Install a timer that will check for new updates every updateInterval seconds and update if available.
 * 
 * @param handle ghota_client_handle_t handle
 * @return esp_err_t ESP_OK if no error, otherwise ESP_FAIL
 */

esp_err_t ghota_start_update_timer(ghota_client_handle_t *handle);

/**
 * @brief convience function to return a string representation of events emited by this library
 * 
 * @param event the eventid passed to the event handler 
 * @return char* a string representing the event
 */
char *ghota_get_event_str(ghota_event_e event);


#ifdef __cplusplus
}
#endif

#endif