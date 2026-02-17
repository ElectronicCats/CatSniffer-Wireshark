/* catsniffer_802154gpi.c
 *
 * SPDX-FileCopyrightText: (C) 2024-2025 Electronic Cats
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Dissector for CatSniffer IEEE 802.15.4g packets (protocol ID 1).
 * This handles Sub-GHz protocols including Wi-SUN and ZigBee R23.
 * Falls back to raw data display for non-standard frames.
 */

#include <epan/packet.h>

#define CATSNIFFER_802154GPI_MIN_LENGTH 4
#define MIN_802154_FRAME_LENGTH 5

// Dissector handles
static dissector_handle_t handle_catsniffer_802154gpi;

// Protocol handles
static int proto_catsniffer_802154gpi;

// Header field handles
static int hf_catsniffer_802154gpi_reserved;
static int hf_catsniffer_802154gpi_payload;
static int hf_catsniffer_802154gpi_raw_data;

// Subtree pointers
static int ett_802154gpi;
static int ett_802154gpi_payload;

// IEEE 802.15.4 dissector handle
static dissector_handle_t wpan_handle;

// Forward declaration
static gboolean is_valid_802154_frame(tvbuff_t *tvb);

static int
dissect_catsniffer_802154gpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // Data is not used...
    (void)data;

    int offset = 0;
    gint payload_len;
    gboolean valid_802154 = FALSE;

    if (tvb_captured_length(tvb) < CATSNIFFER_802154GPI_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.15.4g");

    proto_item *ti = proto_tree_add_item(tree, proto_catsniffer_802154gpi, tvb, 0, -1, ENC_NA);
    proto_tree *ti_802154gpi = proto_item_add_subtree(ti, ett_802154gpi);

    // Reserved 4 bytes (SUN PHI header or padding)
    proto_tree_add_item(ti_802154gpi, hf_catsniffer_802154gpi_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_set_len(ti_802154gpi, offset);

    // Get payload length
    payload_len = tvb_captured_length(tvb) - offset;

    if (payload_len <= 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "No payload");
        return tvb_captured_length(tvb);
    }

    // Get payload tvb
    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, offset);
    add_new_data_source(pinfo, tvb_payload, "802.15.4 Payload");

    // Check if payload looks like valid 802.15.4
    valid_802154 = is_valid_802154_frame(tvb_payload);

    if (valid_802154 && wpan_handle) {
        // Try to dissect as 802.15.4
        int dissected = call_dissector(wpan_handle, tvb_payload, pinfo, tree);
        if (dissected > 0) {
            return tvb_captured_length(tvb);
        }
        // If dissection failed, fall through to raw display
    }

    // Display as raw data (for proprietary/non-standard frames)
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Raw payload");

    proto_tree *payload_tree = proto_tree_add_subtree(ti_802154gpi, tvb, offset, payload_len,
                                                       ett_802154gpi_payload, NULL, "Payload");

    proto_tree_add_item(payload_tree, hf_catsniffer_802154gpi_raw_data, tvb, offset, payload_len, ENC_NA);

    // Also show as hex dump for readability
    proto_tree_add_bytes_item(payload_tree, hf_catsniffer_802154gpi_payload, tvb,
                              offset, payload_len, ENC_NA, NULL, NULL, NULL);

    return tvb_captured_length(tvb);
}

/**
 * Heuristic check if frame looks like valid IEEE 802.15.4
 *
 * Basic checks:
 * - Minimum length (5 bytes for empty ack, typically more)
 * - Frame type is valid (0-3 in Frame Control bits 0-2)
 * - Not all zeros or all 0xFF
 */
static gboolean
is_valid_802154_frame(tvbuff_t *tvb)
{
    gint len;
    guint16 frame_control;
    guint8 frame_type;
    guint8 first_byte, last_byte;
    gint i;
    gboolean all_same = TRUE;
    guint8 prev_byte;

    len = tvb_captured_length(tvb);

    // Too short to be valid 802.15.4
    if (len < MIN_802154_FRAME_LENGTH) {
        return FALSE;
    }

    // Get Frame Control field (first 2 bytes, little-endian)
    frame_control = tvb_get_letohs(tvb, 0);

    // Extract frame type (bits 0-2)
    frame_type = frame_control & 0x07;

    // Valid frame types: 0=Beacon, 1=Data, 2=Ack, 3=MAC Command
    if (frame_type > 3) {
        return FALSE;
    }

    // Check for obviously invalid frames (all same byte value)
    first_byte = tvb_get_guint8(tvb, 0);
    prev_byte = first_byte;

    // Check first 10 bytes or full length if shorter
    for (i = 1; i < len && i < 10; i++) {
        guint8 current = tvb_get_guint8(tvb, i);
        if (current != prev_byte) {
            all_same = FALSE;
            break;
        }
        prev_byte = current;
    }

    // All same byte (like all 0x00 or all 0xFF) is invalid
    if (all_same) {
        return FALSE;
    }

    // Check last byte (often FCS)
    last_byte = tvb_get_guint8(tvb, len - 1);

    // All 0xFF usually indicates noise
    if (first_byte == 0xFF && last_byte == 0xFF) {
        return FALSE;
    }

    return TRUE;
}

void proto_register_catsniffer_802154gpi(void)
{
    // Setup a list of header fields
    static hf_register_info hf[] = {
        {&hf_catsniffer_802154gpi_reserved,
            {"Reserved/SUN PHI", "catsniffer_802154gpi.reserved",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "Reserved bytes or SUN PHI header", HFILL}},

        {&hf_catsniffer_802154gpi_payload,
            {"Payload (hex)", "catsniffer_802154gpi.payload",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Raw payload bytes", HFILL}},

        {&hf_catsniffer_802154gpi_raw_data,
            {"Raw Data", "catsniffer_802154gpi.raw_data",
              FT_NONE, BASE_NONE, NULL, 0x0,
              "Raw payload data (non-802.15.4 format)", HFILL}},
    };

    // Protocol subtree arrays
    static int *ett[] = {
        &ett_802154gpi,
        &ett_802154gpi_payload
    };

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
