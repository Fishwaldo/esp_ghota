idf_component_register(SRCS "main.c")
spiffs_create_partition_image(storage ../spiffs FLASH_IN_PROJECT)