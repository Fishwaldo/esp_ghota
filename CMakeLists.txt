set(priv_requires "log" "freertos" "esp_http_client" "esp-tls" "esp_https_ota" "app_update")
set(requires "esp_event")
set(srcs "src/esp_ghota.c" 
    "src/lwjson_debug.c" 
    "src/lwjson.c" 
    "src/lwjson_stream.c"
    "src/semver.c")

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES ${priv_requires}
                    REQUIRES ${requires})
