/* catsniffer_rpi.c
 *
 * SPDX-FileCopyrightText: © 2024 Antonio Vázquez Blanco <antoniovazquezblanco@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file registers and handles CatSniffer Radio packets following the format shown below.
 *
 * | Version | Length | Interface Type | Interface ID | Protocol | PHY | Frequency | Channel | RSSI | Status | Payload  |
 * |---------|--------|----------------|--------------|----------|-----|-----------|---------|------|--------|----------|
 * | 1B      | 2B     | 1B             | 2B           | 1B       | 1B  | 4B        | 2B      | 1B   | 1B     | Variable |
 *
 * If the received packet is BLE, there is a secondary header with the format below.
 *
 * | Connection Event Counter | Info | Payload         |
 * |--------------------------|------|-----------------|
 * | 2B                       | 1B   | Variable Length |
 *
 */

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <wiretap/wtap.h>

#define TI_RPI_MIN_LENGTH 17

// Dissector handles
static dissector_handle_t handle_catsniffer_rpi;
static dissector_handle_t handle_btle;
static dissector_handle_t handle_wpan;

// Protocol handles
static int proto_catsniffer_rpi;
static int proto_catsniffer_blepi;

// Header field handles
static int hf_catsniffer_rpi_version;
static int hf_catsniffer_rpi_length;
static int hf_catsniffer_rpi_interface_type;
static int hf_catsniffer_rpi_interface_id;
static int hf_catsniffer_rpi_protocol;
static int hf_catsniffer_rpi_phy;
static int hf_catsniffer_rpi_freq;
static int hf_catsniffer_rpi_channel;
static int hf_catsniffer_rpi_rssi;
static int hf_catsniffer_rpi_fcs;
static int hf_catsniffer_blepi_conn_event;

// Subtree pointers
static int ett_rpi;
static int ett_blepi;

// Value tables
static const value_string table_interface_type[] = {
    {0, "COM"},
    {1, "CEBAL"},
    {0, NULL}};

static const value_string table_protocol[] = {
    {0, "Generic"},
    {1, "802.15.4g"},
    {2, "802.15.4"},
    {3, "BLE"},
    {4, "WBMS"},
    {0, NULL}};

static const value_string table_phy[] = {
    {0, "Unused"},
    {3, "O-QPSK"},
    {5, "BLE 1 Mbps"},
    {0, NULL}};

static const unit_name_string table_units_khz = {"kHz", NULL};

static const true_false_string table_fcs = {"Ok", "Bad FCS"};

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
    return offset;
}

static dissector_handle_t get_protocol_dissector_handle(int protocol)
{
    switch (protocol)
    {
    case 2:
        // 802.15.4
        return handle_wpan;
    case 3:
        // BLE
        return handle_btle;
    default:
        return NULL;
    }
}

static int dissect_catsniffer_rpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = 0;
    int length;
    int protocol;

    if (tvb_captured_length(tvb) < TI_RPI_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CatSniffer Radio");

    proto_item *ti = proto_tree_add_item(tree, proto_catsniffer_rpi, tvb, 0, -1, ENC_NA);
    proto_tree *ti_rpi = proto_item_add_subtree(ti, ett_rpi);
    // Version
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_version, tvb, offset, 1, ENC_NA);
    offset += 1;
    // Packet length
    proto_tree_add_item_ret_uint(ti_rpi, hf_catsniffer_rpi_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &length);
    offset += 2;
    // Interface type
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_interface_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    // Interface id
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_interface_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // Protocol
    proto_tree_add_item_ret_uint(ti_rpi, hf_catsniffer_rpi_protocol, tvb, offset, 1, ENC_NA, &protocol);
    offset += 1;
    // PHY
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_phy, tvb, offset, 1, ENC_NA);
    offset += 1;
    // Freq
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_freq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // Channel
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    // RSSI
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_rssi, tvb, offset, 1, ENC_NA);
    offset += 1;
    // Status
    proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_fcs, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_item_set_len(ti_rpi, offset);
    // Optional BLE header
    if (protocol == 3)
    {
        tvbuff_t *tvb_blepi = tvb_new_subset_remaining(tvb, offset);
        offset += dissect_catsniffer_blepi(tvb_blepi, pinfo, tree, data);
    }
    // Payload
    int payload_offset = (protocol == 3) ? 0 : 4;
    tvbuff_t *tvb_payload = tvb_new_subset_remaining(tvb, offset + payload_offset);
    dissector_handle_t payload_dissector = get_protocol_dissector_handle(protocol);
    offset += call_dissector_with_data(payload_dissector, tvb_payload, pinfo, tree, data);
    // All done!
    return offset;
}

void proto_register_catsniffer_rpi(void)
{
    // Setup a list of header fields
    static hf_register_info hf[] = {
        {&hf_catsniffer_rpi_version, {"Version", "catsniffer.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_length, {"Packet Length", "catsniffer.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_interface_type, {"Interface Type", "catsniffer.interface_type", FT_UINT8, BASE_DEC, VALS(table_interface_type), 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_interface_id, {"Interface ID", "catsniffer.interface_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_protocol, {"Protocol", "catsniffer.protocol", FT_UINT8, BASE_DEC, VALS(table_protocol), 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_phy, {"PHY", "catsniffer.phy", FT_UINT8, BASE_DEC, VALS(table_phy), 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_freq, {"Frequency", "catsniffer.freq", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&table_units_khz), 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_channel, {"Channel", "catsniffer.channel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_rssi, {"RSSI", "catsniffer.rssi", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_catsniffer_rpi_fcs, {"Frame Check Status", "catsniffer.fcs", FT_BOOLEAN, 8, TFS(&table_fcs), 0x80, NULL, HFILL}},
        {&hf_catsniffer_blepi_conn_event, {"Connection Event", "catsniffer.conn_event", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    };

    // Protocol subtree arrays
    static int *ett[] = {
        &ett_rpi,
        &ett_blepi};

    // Register protocols
    proto_catsniffer_rpi = proto_register_protocol("CatSniffer Radio Packet Info", "CatSniffer RPI", "catsniffer_rpi");
    proto_catsniffer_blepi = proto_register_protocol("CatSniffer BLE Packet Info", "CatSniffer BLEPI", "catsniffer_blepi");

    // Register dissectors
    handle_catsniffer_rpi = register_dissector("catsniffer_rpi", dissect_catsniffer_rpi, proto_catsniffer_rpi);
    handle_btle = find_dissector("btle");
    handle_wpan = find_dissector("wpan");

    // Register header fields
    proto_register_field_array(proto_catsniffer_rpi, hf, array_length(hf));

    // Register subtrees
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_catsniffer_rpi(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, handle_catsniffer_rpi);
}
