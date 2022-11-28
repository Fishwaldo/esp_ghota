# GITHUB OTA for ESP32 devices

Automate your OTA and CI/CD pipeline with Github Actions to update your ESP32 devices in the field direct from github releases

## Features
* Uses the esp_htps_ota library under the hood to update firmware images
* Can also update spiffs/littlefs/fatfs partitions
* Uses SemVer to compare versions and only update if a newer version is available
* Plays nicely with App rollback and anti-rollback features of the esp-idf bootloader
* Download firmware and partitiion images from the github release page directly
* Supports multiple devices with different firmware images
* Includes a sample Github Actions that builds and releases images when a new tag is pushed
* Updates can be triggered manually, or via a interval timer
* Uses a streaming JSON parser for to reduce memory usage (Github API responses can be huge)
* Supports Private Repositories (Github API token required*)
* Supports Github Enterprise
* Supports Github Personal Access Tokens to overcome Github API Ratelimits
* Sends progress of Updates via the esp_event_loop

Note:
You should be careful with your GitHub PAT and putting it in the source code. I would suggest that you store the PAT in NVS, and the user enters it when running, as otherwise the PAT would be easily extractable from your firmware images. 

## Usage

### esp-idf via Espressif Component Registry:

```bash
idf.py add-dependency Fishwaldo/ghota^0.0.1
```

#### Platform IO Registry:

add this to your platform.ini file:

```ini 
lib_deps = 
    Fishwaldo/ghota@^0.0.1
```

You also need to copy the contents of [Kconfig](Kconfig) into your project's Kconfig file, and run pio run -t menuconfig to configure the component.

#### API Documentation:

More details on the API are available [here](https://esp-github-ota.readthedocs.io/en/latest/index.html)

## Example
After Initilizing Network Access, Start a timer to periodically check for new releases:

(if you a reading this from https://components.espressif.com, please note that this website munges the examples below. Please refer to https://github.com/Fishwaldo/esp_ghota for the correct examples)

```c
    ghota_config_t ghconfig = {
        .filenamematch = "GithubOTA-esp32.bin", // Glob Pattern to match against the Firmware file
        .storagenamematch = "storage-esp32.bin", // Glob Pattern to match against the storage firmware file
        .storagepartitionname = "storage", // Update the storage partition
        .updateInterval = 60, // Check for updates every 60 minuites
    };
    ghota_client_handle_t *ghota_client = ghota_init(&ghconfig);
    if (ghota_client == NULL) {
        ESP_LOGE(TAG, "ghota_client_init failed");
        return;
    }
    esp_event_handler_register(GHOTA_EVENTS, ESP_EVENT_ANY_ID, &ghota_event_callback, ghota_client); // Register a handler to get updates on progress 
    ESP_ERROR_CHECK(ghota_start_update_timer(ghota_client)); // Start the timer to check for updates
```

Manually Checking for updates:

```c
    ghota_config_t ghconfig = {
        .filenamematch = "GithubOTA-esp32.bin",
        .storagenamematch = "storage-esp32.bin",
        .storagepartitionname = "storage",
        .updateInterval = 60,
    };
    ghota_client_handle_t *ghota_client = ghota_init(&ghconfig);
    if (ghota_client == NULL) {
        ESP_LOGE(TAG, "ghota_client_init failed");
        return;
    }
    esp_event_handler_register(GHOTA_EVENTS, ESP_EVENT_ANY_ID, &ghota_event_callback, ghota_client);
    ESP_ERROR_CHECK(ghota_check(ghota_client));

    semver_t *cur = ghota_get_current_version(ghota_client);
    if (cur) {
        ESP_LOGI(TAG, "Current version: %d.%d.%d", cur->major, cur->minor, cur->patch);
        semver_free(cur);
    }

    semver_t *new = ghota_get_latest_version(ghota_client);
    if (new) {
        ESP_LOGI(TAG, "New version: %d.%d.%d", new->major, new->minor, new->patch);
        semver_free(new);
    }
    ESP_ERROR_CHECK(ghota_update(ghota_client));
    ESP_ERROR_CHECK(ghota_free(ghota_client));
```

## Configuration
The following configuration options are available:

    * config.filenamematch <- Glob pattern to match against the firmware file from the Github Releases page. 
    * config.storagenamematch <- Glob pattern to match against the storage file from the Github Releases page.
    * config.storagepartitionname <- Name of the storage partition to update (as defined in partitions.csv)
    * config.hostname <- Hostname of the Github API (default: api.github.com)
    * config.orgname <- Name of the Github User or Organization
    * config.reponame <- Name of the Github Repository
    * config.updateInterval <- Interval in minutes to check for updates

## Github Actions
The Github Actions included in this repository can be used to build and release firmware images to Github Releases.
This is a good way to automate your CI/CD pipeline, and update your devices in the field.
In this example, we build two variants of the Firmware - on for a ESP32 and one for a ESP32-S3 device
Using the filenamematch and storagenamematch config options, we can match against the correct firmware image for the device.

```yaml
on:
  push:
  pull_request:
    branches: [master]

permissions:
  contents: write
name: Build
jobs:
  build:
    strategy:
      fail-fast: true
      matrix: 
        targets: [esp32, esp32s3]
    runs-on: ubuntu-latest
    steps:
    - name: Checkout repo
      uses: actions/checkout@v3
      with:
        submodules: 'recursive'
    - name: esp-idf build
      uses: Fishwaldo/esp-idf-ci-action@v1.1
      with:
        esp_idf_version: v4.4.3
        target: ${{ matrix.targets }}
        path: 'examples/esp_ghota_example'
    - name: Rename artifact
      run: |
        ls -lah 
        cp examples/esp_ghota_example/build/esp_ghota_example.bin esp_ghota_example-${{ matrix.targets }}.bin
        cp examples/esp_ghota_example/build/storage.bin storage-${{ matrix.targets }}.bin
    - name: Archive Firmware Files
      uses: actions/upload-artifact@v3
      with: 
        name: ${{ matrix.targets }}-firmware
        path: "*-${{ matrix.targets }}.bin"

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
    - name: Download Firmware Files
      uses: actions/download-artifact@v2
      with:
        path: release
    - name: Release Firmware
      uses: ncipollo/release-action@v1
      if: startsWith(github.ref, 'refs/tags/') 
      with:
        artifacts: release/*/*.bin
        generateReleaseNotes: true
        allowUpdates: true
        token: ${{ secrets.GITHUB_TOKEN }}
```