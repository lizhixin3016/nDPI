/*
 * ceph.c
 *
 * Copyright (C) 2018-2019 Zhixin Li <abcdlizhixin@gmail.com>
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_CEPH

#include "ndpi_api.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CEPH
#define CEPH_BANNER "ceph v027"
#define CEPH_MSGR_TAG_CLOSE 0X06
#define CEPH_MSGR_TAG_MSG   0X07
#define CEPH_MSGR_TAG_ACK   0X08
#define CEPH_MSGR_TAG_KEEPALIVE 0X09
#define CEPH_MSGR_TAG_KEEPALIVE2 0X0e
#define CEPH_MSGR_TAG_KEEPALIVE2_ACK 0X0f
//#define OFFSET_OF_MSG_FRONT_LEN 23
//#define SIZE_OF_CEPH_MSG_HEADER 53
//#define SIZE_OF_CEPH_MSG_FOOTER 21

struct ceph_entity_name {
  u_int8_t    type; // CEPH_ENTITY_TYPE_*
  u_int64_t   num;
} PACK_OFF;

struct ceph_msg_header {
  u_int64_t seq;       // Sequence number.
  u_int64_t tid;       // Transaction ID.
  u_int16_t type;      // Message type (CEPH_MSG_* or MSG_*).
  u_int16_t priority;  // Priority (higher is more important).
  u_int16_t version;   // Version of message encoding.

  u_int32_t front_len;  // The size of the front section.
  u_int32_t middle_len; // The size of the middle section.
  u_int32_t data_len;   // The size of the data section.
  u_int16_t data_off;   // The way data should be aligned by the reciever.

  //struct ceph_entity_name src; // Information about the sender.
  u_int8_t    src_type; // CEPH_ENTITY_TYPE_*
  u_int64_t   src_num;

  u_int16_t compat_version; // Oldest compatible encoding version.
  u_int16_t reserved;       // Unused.
  u_int32_t crc;            // CRC of header.
} PACK_OFF;

// From src/include/msgr.h
struct ceph_msg_footer {
  u_int32_t front_crc;  // Checksums of the various sections.
  u_int32_t middle_crc; //
  u_int32_t data_crc;   //
  u_int64_t sig;        // Crypographic signature.
  u_int8_t  flags;
} PACK_OFF;

struct ceph_msgr_msg {
  u_int8_t tag;
  struct ceph_msg_header header;
  // u_int8_t front [header.front_len ];
  // u_int8_t middle[header.middle_len];
  // u_int8_t data  [header.data_len  ];
  // struct ceph_msg_footer footer;
} PACK_OFF;

struct ceph_msgr_ack {
  u_int8_t    tag;
  u_int64_t   seq;   // The sequence number of the message being acknowledged.
} PACK_OFF;


static void ndpi_add_ceph_flow(
    struct ndpi_detection_module_struct *ndpi_struct,
    struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CEPH, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_ceph(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search ceph monitor trafiic\n");
  if (packet->tcp != NULL) {
    if(packet->payload_packet_len >= sizeof(struct ceph_msgr_ack)) {
      flow->l4.tcp.packet_num_of_flow++;
      // tag_offset is used to ignore possible multipul message ACK
      u_int32_t tag_offset = 0;
      u_int8_t tag = (u_int8_t *)packet->payload[0];
      if(flow->l4.tcp.packet_num_of_flow <= 2){
        // if is a ceph banner message
        if(memcmp(packet->payload, CEPH_BANNER, 9) == 0){
          NDPI_LOG_INFO(ndpi_struct, "found ceph traffic over tcp\n");
          ndpi_add_ceph_flow(ndpi_struct, flow);
        }
      }

      if(tag == CEPH_MSGR_TAG_ACK) {
        // a packet may have multipul message ACK report and igonre it here
        while(packet->payload_packet_len - tag_offset >= sizeof(struct ceph_msgr_ack)){
          if(tag != CEPH_MSGR_TAG_ACK) break;
          struct ceph_msgr_ack *ack = (struct ceph_msgr_ack *)(packet->payload + tag_offset);
          if(flow->l4.tcp.prev_ceph_tag == CEPH_MSGR_TAG_MSG && ack->seq == flow->l4.tcp.prev_ceph_seq){
            NDPI_LOG_INFO(ndpi_struct, "found ceph traffic over tcp\n");
            ndpi_add_ceph_flow(ndpi_struct, flow);
          }
          tag_offset += sizeof(struct ceph_msgr_ack);
        }
        tag = (u_int8_t *)packet->payload[tag_offset];
      }

      // analysis ceph message
      if(tag == CEPH_MSGR_TAG_MSG && (packet->payload_packet_len - tag_offset > sizeof(struct ceph_msgr_msg))){
        struct ceph_msgr_msg *msg = (struct ceph_msgr_msg*)(packet->payload + tag_offset);
        struct ceph_msg_header h = msg->header;
        //u_int32_t front_len  = *(u_int32_t *)(packet->payload + tag_offset + OFFSET_OF_MSG_FRONT_LEN);
        //u_int32_t middle_len = *(u_int32_t *)(packet->payload + tag_offset + OFFSET_OF_MSG_FRONT_LEN + 2);
        //u_int32_t data_len   = *(u_int32_t *)(packet->payload + tag_offset + OFFSET_OF_MSG_FRONT_LEN + 2);
        //u_int32_t temp = ;
        u_int32_t length = sizeof(struct ceph_msgr_msg) + h.front_len + \
            h.middle_len + h.data_len + sizeof(struct ceph_msg_footer);
        if((length + tag_offset )== packet->payload_packet_len){
          NDPI_LOG_INFO(ndpi_struct, "found ceph traffic over tcp\n");
          ndpi_add_ceph_flow(ndpi_struct, flow);
        }
        flow->l4.tcp.prev_ceph_seq = h.seq;
      }

      flow->l4.tcp.prev_ceph_tag = tag;
    }
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}

void init_ceph_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection(
        "CEPH", ndpi_struct, detection_bitmask, *id,
        NDPI_PROTOCOL_CEPH,
        ndpi_search_ceph,
        NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD,
        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
        ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
