# CatSniffer Wireshark Plugin

This is a native version of a Wireshark plugin to inspect CatSniffer traffic.

## Building

Theoretically, there is a way to build Wireshark plugins out of tree.
Unfortunatelly, there are some outstanding bugs in the way of correctly achieve this feat.
See https://gitlab.com/wireshark/wireshark/-/issues/19976 and https://gitlab.com/wireshark/wireshark/-/issues/1199.
This means there is no good way of building this plugin out of Wireshark source code tree.
The good news is that the plugin can be built inside Wireshark source code and exported as a library to be distributed.

To compile this plugin first checkout Wireshark source code to your preferred wireshark version:
```bash
git clone https://gitlab.com/wireshark/wireshark.git
cd wireshark
git checkout v4.4.0
```

Make sure you have installed all the needed dependencies to build wireshark. You may do that manually (see Wireshark build instructions) or use the setup scripts available inside the Wireshark `tools` folder.
For example for Debian/Ubuntu run:
```bash
tools/debian-setup.sh
```

Then, you need to clone this repository onto the epan plugins folder inside wireshark:
```bash
cd plugins/epan/
git clone https://github.com/ElectronicCats/CatSniffer-Wireshark.git catsniffer
cd ../../
```

In Wireshark main directory, the project must be configured indicating there is an extra plugin.
```bash
cmake -B build -S . -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/catsniffer
```

You may now build the plugin target alone witout having to compile the full Wireshark source code:
```bash
cmake --build build --target catsniffer
cmake --build build --target catsniffersx1262
```


## Running and testing

To test the in-tree build you can perform a full Wireshark build and run the resulting executable:
```bash
cmake --build build
build/run/wireshark
```


## Speciall thanks for contribution:
  - Antonio Vázquez Blanco 
