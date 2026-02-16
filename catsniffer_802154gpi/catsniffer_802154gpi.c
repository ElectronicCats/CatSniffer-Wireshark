/* catsniffer_802154gpi.c
 *
 * SPDX-FileCopyrightText: (C) 2024-2025 Electronic Cats
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Dissector for CatSniffer IEEE 802.15.4g packets (protocol ID 1).
 * This handles Sub-GHz protocols including Wi-SUN and ZigBee R23.
 */

#include <epan/packet.h>

#define CATSNIFFER_802154GPI_MIN_LENGTH 4

// Dissector handles
static dissector_handle_t handle_catsniffer_802154gpi;

// Protocol handles
static int proto_catsniffer_802154gpi;

// Header field handles
static int hf_catsniffer_802154gpi_reserved;

// Subtree pointers
static int ett_802154gpi;

// IEEE 802.15.4 dissector handle
static dissector_handle_t wpan_handle;

static int
dissect_catsniffer_802154gpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // Data is not used...
    (void)data;

    int offset = 0;

    if (tvb_captured_length(tvb) < CATSNIFFER_802154GPI_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.15.4g");

    proto_item *ti = proto_tree_add_item(tree, proto_catsniffer_802154gpi, tvb, 0, -1, ENC_NA);
    proto_tree *ti_802154gpi = proto_item_add_subtree(ti, ett_802154gpi);

    // Reserved 4 bytes (SUN PHI header or padding)
    proto_tree_add_item(ti_802154gpi, hf_catsniffer_802154gpi_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_set_len(ti_802154gpi, offset);

    // Pass remaining payload to wpan dissector
    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, offset);
    add_new_data_source(pinfo, tvb_payload, "802.15.4 Payload");

    if (wpan_handle) {
        call_dissector(wpan_handle, tvb_payload, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

void proto_register_catsniffer_802154gpi(void)
{
    // Setup a list of header fields
    static hf_register_info hf[] = {
        {&hf_catsniffer_802154gpi_reserved,
            {"Reserved/SUN PHI", "catsniffer_802154gpi.reserved",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "Reserved bytes or SUN PHI header", HFILL}},
    };

    // Protocol subtree arrays
    static int *ett[] = {
        &ett_802154gpi};

    // Register protocols
    proto_catsniffer_802154gpi = proto_register_protocol(
        "CatSniffer 802.15.4g Packet Info",
        "CatSniffer 802.15.4g PI",
        "catsniffer_802154gpi");

    // Register dissectors
    handle_catsniffer_802154gpi = register_dissector("catsniffer_802154gpi",
        dissect_catsniffer_802154gpi, proto_catsniffer_802154gpi);

    // Register header fields
    proto_register_field_array(proto_catsniffer_802154gpi, hf, array_length(hf));

    // Register subtrees
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_catsniffer_802154gpi(void)
{
    // Register to catsniffer_rpi protocol table entry 1 (802.15.4g)
    dissector_add_uint("catsniffer_rpi.protocol", 1, handle_catsniffer_802154gpi);

    // Find wpan dissector for payload handling
    wpan_handle = find_dissector("wpan");
}
