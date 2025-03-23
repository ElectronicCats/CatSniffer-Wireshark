/* catsniffer_wpanpi.c
 *
 * SPDX-FileCopyrightText: © 2024-2025 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file registers and handles CatSniffer WPAN (802.15.4) Radio packets following the format shown below.
 *
 * | Reserved   |
 * |------------|
 * | 4B         |
 */

#include <epan/packet.h>

// Dissector handles
static dissector_handle_t handle_catsniffer_wpanpi;
static dissector_handle_t handle_wpan;

// Protocol handles
static int proto_catsniffer_wpanpi;

// Header field handles
static int hf_catsniffer_wpanpi_reserved;

// Subtree pointers
static int ett_wpanpi;

static int dissect_catsniffer_wpanpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    (void)data;
    if (tvb_reported_length(tvb) == 0)
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Catsniffer WPAN");
    proto_item *ti = proto_tree_add_item(tree, proto_catsniffer_wpanpi, tvb, 0, -1, ENC_NA);
    proto_tree *ti_wpanpi = proto_item_add_subtree(ti, ett_wpanpi);
    //  Connection Event
    proto_tree_add_item(ti_wpanpi, hf_catsniffer_wpanpi_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_item_set_len(ti_wpanpi, offset);
    // Handoff to next protocols
    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, offset);
    offset += call_dissector_with_data(handle_wpan, tvb_payload, pinfo, tree, data);
    // All done!
    return offset;
}

void proto_register_catsniffer_wpanpi(void)
{
    // Setup a list of header fields
    static hf_register_info hf[] = {
        {&hf_catsniffer_wpanpi_reserved, {"Reserved", "catsniffer.reserved", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    };

    // Protocol subtree arrays
    static int *ett[] = {
        &ett_wpanpi};

    // Register protocols
    proto_catsniffer_wpanpi = proto_register_protocol("CatSniffer WPAN Packet Info", "CatSniffer WPANPI", "catsniffer_wpanpi");

    // Register dissectors
    handle_catsniffer_wpanpi = register_dissector("catsniffer_wpanpi", dissect_catsniffer_wpanpi, proto_catsniffer_wpanpi);
    handle_wpan = find_dissector("wpan");

    // Register header fields
    proto_register_field_array(proto_catsniffer_wpanpi, hf, array_length(hf));

    // Register subtrees
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_catsniffer_wpanpi(void)
{
    dissector_add_uint("catsniffer_rpi.protocol", 2, handle_catsniffer_wpanpi);
}
