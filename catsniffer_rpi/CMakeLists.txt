# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2024-2025 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
# SPDX-License-Identifier: GPL-2.0-or-later

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(catsniffer_rpi 0 0 1 0)

set(DISSECTOR_SRC
	catsniffer_rpi.c
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

add_wireshark_plugin_library(catsniffer_rpi epan)

target_link_libraries(catsniffer_rpi epan)

install_plugin(catsniffer_rpi epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
    catsniffer_rpi
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

# This is a subtarget of the virtual catsniffer target
add_dependencies(catsniffer catsniffer_rpi)
