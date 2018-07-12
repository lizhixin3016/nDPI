/*
 * mongodb.c
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

#ifdef NDPI_PROTOCOL_MONGODB

#include "ndpi_api.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MONGODB

#define OP_REPLY	    1	    // Reply to a client request. responseTo is set.
#define OP_UPDATE       2001    // Update document.
#define OP_INSERT       2002    // Insert new document.
#define OP_RESERVED     2003    // Formerly used for OP_GET_BY_OID.
#define OP_QUERY        2004    // Query a collection.
#define OP_GET_MORE     2005    // Get more data from a query. See Cursors.
#define OP_DELETE       2006    // Delete documents.
#define OP_KILL_CURSORS	2007	// Notify database that the client has finished with the cursor.
#define OP_COMMAND	    2010	// Cluster internal protocol representing a command request.
#define OP_COMMANDREPLY 2011    // Cluster internal protocol representing a reply to an #define OP_COMMAND.
#define OP_MSG      	2013	// Send a message using the format introduced in MongoDB 3.6.

#define REPLAY_DOCUMENT_OFFSET  36  // offset of document

PACK_ON
struct mongo_msg_header
{
    u_int32_t message_len;      // total message size, including this
    u_int32_t request_id;       // identifier for this message
    u_int32_t response_id;      // requestID from the original request (used in responses from db)
    u_int32_t op_code;          // Operation code id of the request
} PACK_OFF;

struct mongo_msg_query
{
    u_int32_t flags;                // bit vector of query options.  See below for details.
    char     *collection_name;      // "dbname.collectionname"
    u_int32_t number_skip;          // number of documents to skip
    u_int32_t number_return;        // number of documents to return
                                    //  in the first OP_REPLY batch
    u_int32_t doc_length;           // query object.  See below for details.
    char     *document;             // Optional. Selector indicating the fields
} PACK_OFF;

struct mongo_msg_reply
{
    u_int32_t responseFlags;  // bit vector - see details below
    u_int64_t cursorID;       // cursor id if client needs to do get more's
    u_int32_t startingFrom;   // where in the cursor this reply is starting
    u_int32_t numberReturned; // number of documents in the reply
    char     *documents;      // documents
} PACK_OFF;


static void ndpi_add_mongodb_flow(
    struct ndpi_detection_module_struct *ndpi_struct,
    struct ndpi_flow_struct *flow)
{
    NDPI_LOG_INFO(ndpi_struct, "found mongodb traffic over tcp\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MONGODB, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_mongodb(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;

    NDPI_LOG_DBG(ndpi_struct, "search mongodb monitor trafiic\n");
    if (packet->tcp != NULL && packet->payload_packet_len >= sizeof(struct mongo_msg_header))
    {
        struct mongo_msg_header *header = (struct mongo_msg_header *)(packet->payload);
        if (packet->payload_packet_len == header->message_len)
        {
            flow->l4.tcp.packet_num_of_flow++;
            if (header->op_code == OP_REPLY && header->response_id == flow->l4.tcp.prev_mongo_reqid)
            {
                ndpi_add_mongodb_flow(ndpi_struct, flow);
            }
            if (header->op_code == OP_QUERY || header->op_code == OP_GET_MORE ||
                header->op_code == OP_UPDATE || header->op_code == OP_INSERT ||
                header->op_code == OP_DELETE || header->op_code == OP_KILL_CURSORS ||
                header->op_code == OP_MSG || header->op_code == OP_COMMAND || header->op_code == OP_COMMANDREPLY)
            {
                flow->l4.tcp.prev_mongo_opcode = header->op_code;
                flow->l4.tcp.prev_mongo_reqid = header->request_id;
            }
        }
        else
        {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        }
    }
    else
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
}

void init_mongodb_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection(
        "MongoDB", ndpi_struct, detection_bitmask, *id,
        NDPI_PROTOCOL_MONGODB,
        ndpi_search_mongodb,
        NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD,
        SAVE_DETECTION_BITMASK_AS_UNKNOWN,
        ADD_TO_DETECTION_BITMASK);

    *id += 1;
}

#endif
