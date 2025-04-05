/* catsniffer_blepi.c
 *
 * SPDX-FileCopyrightText: © 2024-2025 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file registers and handles CatSniffer BLE Radio packets following the format shown below.
 *
 * | Connection Event Counter | Info | Payload         |
 * |--------------------------|------|-----------------|
 * | 2B                       | 1B   | Variable Length |
 */

#include <epan/packet.h>

// Dissector handles
static dissector_handle_t handle_catsniffer_blepi;
static dissector_handle_t handle_btle;

// Protocol handles
static int proto_catsniffer_blepi;

// Header field handles
static int hf_catsniffer_blepi_conn_event;

// Subtree pointers
static int ett_blepi;

static int dissect_catsniffer_blepi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    (void)data;
    if (tvb_reported_length(tvb) == 0)
        return 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Catsniffer BLE");
    proto_item *ti = proto_tree_add_item(tree, proto_catsniffer_blepi, tvb, 0, -1, ENC_NA);
    proto_tree *ti_blepi = proto_item_add_subtree(ti, ett_blepi);
    //  Connection Event
    proto_tree_add_item(ti_blepi, hf_catsniffer_blepi_conn_event, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_item_set_len(ti_blepi, offset);
    // Handoff to next protocols
    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, offset);
    offset += call_dissector_with_data(handle_btle, tvb_payload, pinfo, tree, data);
    // All done!
    return offset;
}

void proto_register_catsniffer_blepi(void)
{
    // Setup a list of header fields
    static hf_register_info hf[] = {
        {&hf_catsniffer_blepi_conn_event, {"Connection Event", "catsniffer.conn_event", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    };

    // Protocol subtree arrays
    static int *ett[] = {
        &ett_blepi};

    // Register protocols
    proto_catsniffer_blepi = proto_register_protocol("CatSniffer BLE Packet Info", "CatSniffer BLEPI", "catsniffer_blepi");

    // Register dissectors
    handle_catsniffer_blepi = register_dissector("catsniffer_blepi", dissect_catsniffer_blepi, proto_catsniffer_blepi);
    handle_btle = find_dissector("btle");

    // Register header fields
    proto_register_field_array(proto_catsniffer_blepi, hf, array_length(hf));

    // Register subtrees
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_catsniffer_blepi(void)
{
    dissector_add_uint("catsniffer_rpi.protocol", 3, handle_catsniffer_blepi);
}
