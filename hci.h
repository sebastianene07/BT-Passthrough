#ifndef __BT_PASSTHROUGH_HCI_H
#define __BT_PASSTHROUGH_HCI_H

#include <stdint.h>

typedef union __attribute__((__packed__)) hci_opcode_u {
  uint16_t opcode;
  struct __attribute__((__packed__)) opcode_s {
    uint16_t ocf : 10;
    uint16_t ogf : 6;
  } opcode_t;
} hci_opcode_t;

typedef enum h4_hci_type_e {
  H4_HCI_TYPE_CMD  = 0x01,
  H4_HCI_TYPE_ACL,
  H4_HCI_TYPE_SCO,
  H4_HCI_TYPE_EVT,
  H4_HCI_TYPE_INVALID,
} h4_hci_type_t;

typedef struct __attribute__((__packed__)) hci_cmd_packet_s {
  hci_opcode_t op;
  uint8_t param_len;
  uint8_t params[0];
} hci_cmd_packet_t;

typedef struct __attribute__((__packed__)) hci_acl_packet_s {
  uint16_t handle : 12;
  uint16_t pb_flag : 2;
  uint16_t bc_flag : 2;
  uint16_t data_total_len;
  uint8_t data[0];
} hci_acl_packet_t;

typedef struct __attribute__((__packed__)) hci_sco_packet_s {
  uint16_t conn_handle : 12;
  uint16_t packet_status_flag : 2;
  uint16_t rfu : 2;
  uint8_t data_total_len;
} hci_sco_packet_t;

typedef union h4_hci_pkt_type_u {
  hci_cmd_packet_t cmd;
  hci_acl_packet_t acl;
  hci_sco_packet_t sco;
} h4_hci_pkt_type_t;

typedef struct h4_hci_pkt_s {
  uint8_t h4_type;
  h4_hci_pkt_type_t pkt;
} h4_hci_pkt_t;

#endif /* __BT_PASSTHROUGH_HCI_H */
