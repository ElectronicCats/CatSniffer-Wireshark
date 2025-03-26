# CMakeLists.txt
#
# SPDX-FileCopyrightText: © 2024-2025 Kevin Leon
# SPDX-FileCopyrightText: © 2024-2025 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.10)

project(CatSnifferPlugins)

# Create a virtual target that groups all CatSniffer targets
add_custom_target(catsniffer ALL)

# Add all the targets
add_subdirectory(catsniffer_rpi)
add_subdirectory(catsniffersx1262)
