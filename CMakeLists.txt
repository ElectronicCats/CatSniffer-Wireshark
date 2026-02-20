# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2024-2025 Kevin Leon
# SPDX-FileCopyrightText: © 2024-2025 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.10)

project(CatSnifferPlugins)

# Create a virtual target that groups all CatSniffer targets
add_custom_target(catsniffer ALL)

add_subdirectory(catsniffer_rpi)
add_subdirectory(catsniffer_blepi)
add_subdirectory(catsniffer_wpanpi)
add_subdirectory(catsniffer_802154gpi)
add_subdirectory(catsniffersx1262)
