cmake_minimum_required(VERSION 3.14.0)
project(PcieTest VERSION 1.3.0)
get_verstring(VERSTRING)

add_link_options(-ffreestanding -m68040 -nostdlib -nostartfiles -Wl,-e,__start)
add_compile_options(-Os -m68040 -fomit-frame-pointer)
add_compile_definitions(PRIVATE VERSION_STRING="${VERSTRING}")

add_executable(${PROJECT_NAME}
    src/main.c
)

target_link_libraries(${PROJECT_NAME} amiga devicetree)

target_include_directories(${PROJECT_NAME} PRIVATE include)

add_custom_command(
        OUTPUT ${PROJECT_SOURCE_DIR}/${PROJECT_NAME}.info
        COMMAND ilbmtoicon
        --png
        ""
        bogdan.png
        PcieTest.info
        COMMENT "Generating Aminet readme file..."
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        VERBATIM
)

add_custom_target(icon DEPENDS ${PROJECT_BINARY_DIR}/${PROJECT_NAME}.info)

add_dependencies(${PROJECT_NAME} icon)


install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/PcieTest DESTINATION ./PcieTest/)
install(FILES PcieTest.info DESTINATION ./PcieTest/)
