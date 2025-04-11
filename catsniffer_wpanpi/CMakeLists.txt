# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2024-2025 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(catsniffer_wpanpi 0 0 1 0)

set(DISSECTOR_SRC
	catsniffer_wpanpi.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(catsniffer_wpanpi epan)

target_link_libraries(catsniffer_wpanpi epan)

install_plugin(catsniffer_wpanpi epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
    catsniffer_wpanpi
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

add_dependencies(catsniffer catsniffer_wpanpi)
