
#include "secure_communications_service.h"

#include "app_features.h"
#include "secure_session_manager.h"
#include "secure_session_manager_internal.h"
#include "msg_dispatcher_tagged_endpoint_registry.h"
#include "msg_dispatcher.h"
#include "client_message_parser.h"
#include "identity_authentication.h"
#include "sl_sleeptimer.h"
#include "sl_se_manager_entropy.h"
#include "debug_logger.h"
#include "common_helpers.h"

#include "stdio.h"

#define NONCE_SIZE                                            32
#define SIGNATURE_SIZE                                        64
#define PUBKEY_SIZE                                           64
#define HALF_NONCE_SIZE                                       (NONCE_SIZE / 2)
#define HALF_SIGNATURE_SIZE                                   (SIGNATURE_SIZE / 2)
#define HALF_PUBKEY_SIZE                                      (PUBKEY_SIZE / 2)
#define EXPECTED_REQUEST_MSG_PAYLOAD_SIZE                     (NONCE_SIZE + SIGNATURE_SIZE)
#define REQUEST_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE           (HALF_NONCE_SIZE + HALF_SIGNATURE_SIZE)
#define EXPECTED_REQUEST_MSG_SIZE                             (MSG_SIZE_INCLUDING_FIELD(AUTH_LEN) + EXPECTED_REQUEST_MSG_PAYLOAD_SIZE)
#define REQUEST_CHALLENGE_RESPONSE_SIZE                       (MSG_SIZE_INCLUDING_FIELD(LEN) + REQUEST_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE)
#define EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE   (HALF_SIGNATURE_SIZE + HALF_PUBKEY_SIZE + SIGNATURE_SIZE)
#define EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_SIZE           (MSG_SIZE_INCLUDING_FIELD(AUTH_LEN) + EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE)
#define PUBKEY_RESPONSE_MSG_PAYLOAD_SIZE                      (HALF_SIGNATURE_SIZE + HALF_PUBKEY_SIZE)
#define PUBKEY_RESPONSE_MSG_SIZE                              (MSG_SIZE_INCLUDING_FIELD(LEN) + PUBKEY_RESPONSE_MSG_PAYLOAD_SIZE)
#define CALCULATION_COMPLETE_MSG_PAYLOAD_SIZE                 (NONCE_SIZE)
#define CALCULATION_COMPLETE_MSG_SIZE                         (MSG_SIZE_INCLUDING_FIELD(LEN) + CALCULATION_COMPLETE_MSG_PAYLOAD_SIZE)
#define MS_BETWEEN_MSGS                                       10

#define CLIENT_CHALLENGE                                      (THE_FIELD_AFTER(AUTH_LEN))
#define CHALLENGE_RESPONSE                                    (THE_FIELD_AFTER(LEN))
#define CLIENT_CHALLENGE_RESPONSE                             (THE_FIELD_AFTER(AUTH_LEN))
#define DEV_CHALLENGE                                         (CHALLENGE_RESPONSE + HALF_SIGNATURE_SIZE)
#define CLIENT_PUBKEY                                         (CLIENT_CHALLENGE_RESPONSE + HALF_SIGNATURE_SIZE)
#define CLIENT_PUBKEY_RESPONSE                                (THE_FIELD_AFTER(LEN))
#define DEV_PUBKEY                                            (CLIENT_PUBKEY_RESPONSE + HALF_SIGNATURE_SIZE)
#define CALC_COMPLETE_NONCE                                   (THE_FIELD_AFTER(LEN))

#define REQUEST            0x07
#define REQUEST_RESPONSE_1 0x08
#define REQUEST_RESPONSE_2 0x09
#define CLIENT_PUBKEY_1    0x0A
#define CLIENT_PUBKEY_2    0x0B
#define PUBKEY_RESPONSE_1  0x0C
#define PUBKEY_RESPONSE_2  0x0D
#define CALC_COMPLETE      0x0E


#define SECURE_COMMS_DEBUG_ID         0x02
#define COMMS_ALREADY_SECURE          0x01
#define CHALLENGE_VERIFY_FAILED       0x02
#define SET_CLIENT_PUBKEY_FAILED      0x05
#define INVALID_OPCDODE               0x08
#define INVALID_MSG_SIZE              0x09
#define SHORT_MSG_HEADER              0x0A

static msg_dispatcher_t* msg_dispatcher = NULL;
static endpoint_t dispatcher_endpoint;

bool first_client_response_set = false;
static uint8_t dev_challenge_response_buffer[SIGNATURE_SIZE] = {0};

static uint8_t client_pubkey_buffer[PUBKEY_SIZE] = {0};


typedef struct {
   uint8_t* challenge;

} ecdh_request_msg_t;

typedef struct {
   uint8_t* half_signature;
   uint8_t* half_dev_challenge;
} ecdh_request_challenge_response;

typedef struct {
   authenticated_msg_header_t header;
   union {
      ecdh_request_msg_t request;
      ecdh_request_challenge_response response;
   };
} ecdh_msg_t;

static void parse_request_msg(ecdh_msg_t* msg_out, uint8_t* msg_in, size_t msg_in_size) {

   if (msg_out->header.base_header.len >= EXPECTED_REQUEST_MSG_PAYLOAD_SIZE && msg_in_size >= EXPECTED_REQUEST_MSG_SIZE) {
         msg_out->request.challenge = msg_in + CLIENT_CHALLENGE;
   }
}

static void parse_client_challenge_response(ecdh_msg_t* msg_out, uint8_t* msg_in, size_t msg_in_size) {
   if (msg_out->header.base_header.len >= EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE && msg_in_size >= EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_SIZE) {
         msg_out->response.half_signature = msg_in + CLIENT_CHALLENGE_RESPONSE;
         msg_out->response.half_dev_challenge = msg_in + CLIENT_PUBKEY;
   }
}

static size_t pack_challenge_response(ecdh_msg_t* msg_in, uint8_t* msg_out, size_t msg_out_size) {

   if (msg_out_size < REQUEST_CHALLENGE_RESPONSE_SIZE) {
         return 0;
   }

   msg_in->header.base_header.routing_id = ECDH_MSG_EXCHANGE_OUTBOUND_HANDLER_ID;
   pack_header(&msg_in->header.base_header, msg_out);
   memcpy(msg_out + CHALLENGE_RESPONSE, msg_in->response.half_signature, HALF_SIGNATURE_SIZE);
   memcpy(msg_out + DEV_CHALLENGE, msg_in->response.half_dev_challenge, HALF_NONCE_SIZE);
   return REQUEST_CHALLENGE_RESPONSE_SIZE;

}

static size_t pack_public_key_response(ecdh_msg_t* msg_in, uint8_t* msg_out, size_t msg_out_size) {
   if (msg_out_size < PUBKEY_RESPONSE_MSG_SIZE) {
         return 0;
   }

   msg_in->header.base_header.routing_id = ECDH_MSG_EXCHANGE_OUTBOUND_HANDLER_ID;
   pack_header(&msg_in->header.base_header, msg_out);
   memcpy(msg_out + CLIENT_PUBKEY_RESPONSE, msg_in->response.half_signature, HALF_SIGNATURE_SIZE);
   memcpy(msg_out + DEV_PUBKEY, msg_in->response.half_dev_challenge, HALF_PUBKEY_SIZE);
   return PUBKEY_RESPONSE_MSG_SIZE;

}

static void parse_ecdh_msg(ecdh_msg_t* msg_out, uint8_t* msg_in, size_t msg_in_size) {

   if (msg_in_size < MSG_HEADER_SIZE) {
         return;
   }

   parse_authenticated_header(&msg_out->header, msg_in, msg_in_size);

   if (msg_out->header.base_header.opcode == REQUEST) {
         parse_request_msg(msg_out, msg_in, msg_in_size);
   } else if (msg_out->header.base_header.opcode == CLIENT_PUBKEY_1 || msg_out->header.base_header.opcode == CLIENT_PUBKEY_2) {
         parse_client_challenge_response(msg_out, msg_in, msg_in_size);
   }
}

static bool dispatch_msgs(endpoint_t* endpoint, uint8_t** msgs, uint8_t* msg_sizes, uint8_t num_msgs) {


  if (num_msgs > 0) {
     if (!msg_dispatcher_dispatch(msg_dispatcher, endpoint, &dispatcher_endpoint, msgs[0], msg_sizes[0])) {
         return false;
     }
     for (int i = 1; i < num_msgs; ++i) {
           sl_sleeptimer_delay_millisecond(MS_BETWEEN_MSGS);
         if (!msg_dispatcher_dispatch(msg_dispatcher, endpoint, &dispatcher_endpoint, msgs[i], msg_sizes[i])) {
             return false;
         }
     }
  }
  return true;

}

static bool build_and_send_request_response(uint8_t* challenge_signature, endpoint_t* endpoint) {

   uint8_t response_challenge[NONCE_SIZE];
   secure_session_challenge_t challenge = {.buffer = response_challenge, .buffer_len = NONCE_SIZE};
   secure_session_manager_start_session();
   if (secure_session_manager_get_session_challenge(&challenge)) {

         uint8_t response_msg_1[REQUEST_CHALLENGE_RESPONSE_SIZE];
         ecdh_msg_t response;
         response.header.base_header.opcode = REQUEST_RESPONSE_1;
         response.header.base_header.len = REQUEST_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE + SIGNATURE_SIZE;
         response.response.half_signature = challenge_signature;
         response.response.half_dev_challenge = response_challenge;

         size_t actual_response_size_1 = pack_challenge_response(&response, response_msg_1, REQUEST_CHALLENGE_RESPONSE_SIZE);

         uint8_t response_msg_2[REQUEST_CHALLENGE_RESPONSE_SIZE];
         response.header.base_header.opcode = REQUEST_RESPONSE_2;
         response.response.half_signature = challenge_signature + HALF_SIGNATURE_SIZE;
         response.response.half_dev_challenge = response_challenge + HALF_NONCE_SIZE;

         size_t actual_response_size_2 = pack_challenge_response(&response, response_msg_2, REQUEST_CHALLENGE_RESPONSE_SIZE);

         uint8_t* responses[] = {response_msg_1, response_msg_2};
         uint8_t msg_sizes[] = {actual_response_size_1, actual_response_size_2};
         if (!dispatch_msgs(endpoint, responses, msg_sizes, ARRAY_SIZE(responses))) {
               return false;
         }

   } else {
         return false;
   }
   return true;
}

static bool build_and_send_public_key_response(endpoint_t* endpoint) {
   secure_session_challenge_t dev_challenge_response = {.buffer = dev_challenge_response_buffer, .buffer_len = SIGNATURE_SIZE};
   secure_session_public_key_t client_pubkey = {.buffer = client_pubkey_buffer, .buffer_len = PUBKEY_SIZE};
   uint8_t client_pubkey_signature[SIGNATURE_SIZE] = {0};
   uint8_t dev_pubkey_buffer[PUBKEY_SIZE] = {0};
   secure_session_public_key_t dev_pubkey = {.buffer = dev_pubkey_buffer, .buffer_len = PUBKEY_SIZE};
   uint8_t error_code = 0;

   if (!secure_session_manager_verify_session_challenge_response(&dev_challenge_response)) {
       error_code = CHALLENGE_VERIFY_FAILED;
   } else if (identity_authentication_sign(client_pubkey.buffer, client_pubkey.buffer_len, client_pubkey_signature, SIGNATURE_SIZE)) {

       if (!secure_session_manager_set_client_pubkey(&client_pubkey)) {
           error_code = SET_CLIENT_PUBKEY_FAILED;
       } else if (secure_session_manager_get_dev_pubkey(&dev_pubkey)) {


             uint8_t pubkey_response_1[PUBKEY_RESPONSE_MSG_SIZE] = {0};
             ecdh_msg_t pubkey_response_msg;
             pubkey_response_msg.header.base_header.opcode = PUBKEY_RESPONSE_1;
             pubkey_response_msg.header.base_header.len = PUBKEY_RESPONSE_MSG_PAYLOAD_SIZE + SIGNATURE_SIZE;
             pubkey_response_msg.response.half_signature = client_pubkey_signature;
             pubkey_response_msg.response.half_dev_challenge = dev_pubkey_buffer;

             size_t actual_msg_size_1 = pack_public_key_response(&pubkey_response_msg, pubkey_response_1, PUBKEY_RESPONSE_MSG_SIZE);

             uint8_t pubkey_response_2[PUBKEY_RESPONSE_MSG_SIZE] = {0};
             pubkey_response_msg.header.base_header.opcode = PUBKEY_RESPONSE_2;
             pubkey_response_msg.response.half_signature = client_pubkey_signature + HALF_SIGNATURE_SIZE;
             pubkey_response_msg.response.half_dev_challenge = dev_pubkey_buffer + HALF_PUBKEY_SIZE;

             size_t actual_msg_size_2 = pack_public_key_response(&pubkey_response_msg, pubkey_response_2, PUBKEY_RESPONSE_MSG_SIZE);

             uint8_t calculation_complete[CALCULATION_COMPLETE_MSG_SIZE] = {ECDH_MSG_EXCHANGE_OUTBOUND_HANDLER_ID, CALC_COMPLETE, NONCE_SIZE + SIGNATURE_SIZE};
             sl_se_command_context_t cmd_ctx;
             sl_se_get_random(&cmd_ctx, calculation_complete + CALC_COMPLETE_NONCE, NONCE_SIZE);

             uint8_t* responses[] = {pubkey_response_1, pubkey_response_2, calculation_complete};
             uint8_t msg_sizes[] = {actual_msg_size_1, actual_msg_size_2, CALCULATION_COMPLETE_MSG_SIZE};
             if (!dispatch_msgs(endpoint, responses, msg_sizes, ARRAY_SIZE(responses))) {
               return false;
             }
             return true;
         }
   }

   debug_event(SECURE_COMMS_DEBUG_ID, error_code);
   return false;
}

static bool handle_request_msg(endpoint_t* endpoint, ecdh_msg_t* msg) {
  if (msg->header.base_header.opcode == REQUEST) {
      if (msg->header.base_header.len >= EXPECTED_REQUEST_MSG_PAYLOAD_SIZE && msg->header.base_header.raw_data_size >= EXPECTED_REQUEST_MSG_SIZE) {

          uint8_t challenge_signature[SIGNATURE_SIZE];

          if (identity_authentication_sign(msg->request.challenge, NONCE_SIZE, challenge_signature, SIGNATURE_SIZE)) {

              return build_and_send_request_response(challenge_signature, endpoint);
          }
      } else {
          uint8_t msg_sizes[] = {msg->header.base_header.opcode, msg->header.base_header.len, msg->header.base_header.raw_data_size};
          debug_event_with_data(SECURE_COMMS_DEBUG_ID, INVALID_MSG_SIZE, msg_sizes, sizeof(msg_sizes));
      }
  } else {
      debug_event_with_data(SECURE_COMMS_DEBUG_ID, INVALID_OPCDODE, &msg->header.base_header.opcode, sizeof(msg->header.base_header.opcode));
  }
  return false;
}


static bool handle_client_pubkey_response(endpoint_t* endpoint, ecdh_msg_t* msg) {

  if (msg->header.base_header.len >= EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_PAYLOAD_SIZE && msg->header.base_header.raw_data_size >= EXPECTED_CLIENT_CHALLENGE_RESPONSE_MSG_SIZE) {

         uint8_t sig_offset = msg->header.base_header.opcode == CLIENT_PUBKEY_1 ? 0 : HALF_SIGNATURE_SIZE;
         uint8_t pubkey_offset = msg->header.base_header.opcode == CLIENT_PUBKEY_1 ? 0 : HALF_PUBKEY_SIZE;

         memcpy(dev_challenge_response_buffer + sig_offset, msg->response.half_signature, HALF_SIGNATURE_SIZE);
         memcpy(client_pubkey_buffer + pubkey_offset, msg->response.half_dev_challenge, HALF_PUBKEY_SIZE);

         if (msg->header.base_header.opcode == CLIENT_PUBKEY_1) {
             first_client_response_set = true;
         } else if (msg->header.base_header.opcode == CLIENT_PUBKEY_2) {
             return build_and_send_public_key_response(endpoint);
         }


   } else {
       uint8_t msg_sizes[] = {msg->header.base_header.opcode, msg->header.base_header.len, msg->header.base_header.raw_data_size};
       debug_event_with_data(SECURE_COMMS_DEBUG_ID, INVALID_MSG_SIZE, msg_sizes, sizeof(msg_sizes));
       return false;
   }

  return true;

}


static void msg_handler(endpoint_t* endpoint, uint8_t* data, size_t data_size) {

   if (secure_session_manager_is_secured()) {
       debug_event(SECURE_COMMS_DEBUG_ID, COMMS_ALREADY_SECURE);
         return;
   }

   bool processing_succeeded = false;
   if (data_size >= MSG_HEADER_SIZE) {

         ecdh_msg_t msg = {.header.base_header.opcode = 0, .header.base_header.len = 0, .response = {.half_signature = NULL, .half_dev_challenge = NULL}};
         parse_ecdh_msg(&msg, data, data_size);

         if (!secure_session_manager_is_started()) {
             processing_succeeded = handle_request_msg(endpoint, &msg);
         } else {
             if (msg.header.base_header.opcode == CLIENT_PUBKEY_1 || msg.header.base_header.opcode == CLIENT_PUBKEY_2) {
                 processing_succeeded = handle_client_pubkey_response(endpoint, &msg);
             } else {
                 debug_event_with_data(SECURE_COMMS_DEBUG_ID, INVALID_OPCDODE, &msg.header.base_header.opcode, sizeof(msg.header.base_header.opcode));
             }
         }
   } else {
       debug_event_with_data(SECURE_COMMS_DEBUG_ID, SHORT_MSG_HEADER, (uint8_t*)&data_size, sizeof(data_size));
   }

   if(!processing_succeeded) {
         secure_session_manager_stop_session();
   }

}

void secure_communications_service_init(msg_dispatcher_t* dispatcher) {


   msg_dispatcher = dispatcher;
   msg_dispatcher_tagged_endpoint_registry_add(SECURE_COMMS_SERVICE_ENDPOINT, msg_handler);
   dispatcher_endpoint = msg_dispatcher_create_endpoint(msg_handler);

}
