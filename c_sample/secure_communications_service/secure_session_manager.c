
#include "secure_session_manager.h"
#include "secure_session_manager_internal.h"
#include "sl_se_manager_key_handling.h"
#include "sl_se_manager_key_derivation.h"
#include "sl_se_manager_defines.h"
#include "sl_se_manager_entropy.h"
#include "sl_se_manager_cipher.h"
#include "sl_se_manager_types.h"
#include "identity_authentication.h"
#include "common_key_descriptors.h"
#include <string.h>

#include "stdio.h"


#define IV_SIZE 16
#define CHALLENGE_SIZE 32

#define CIPHER_BLOCK_SIZE 16

#define AES_KEY_START    7
#define AES_KEY_END     22
#define IV_PART_1_SIZE   (AES_KEY_START)
#define IV_PART_1_START  0
#define IV_PART_1_END   (IV_PART_1_START + (IV_PART_1_SIZE - 1))
#define IV_PART_2_SIZE  (IV_SIZE - IV_PART_1_SIZE)
#define IV_PART_2_START (AES_KEY_END + 1)
#define IV_PART_2_END   (IV_PART_2_START + (IV_PART_2_SIZE - 1))

#define  AES128_KEY_STORE_DESC {                                         \
         .type = SL_SE_KEY_TYPE_AES_128,                                 \
         .flags = SL_SE_KEY_FLAG_NON_EXPORTABLE,                         \
         .size = AES128_KEY_SIZE,                                        \
         .storage = {                                                    \
               .method = SL_SE_KEY_STORAGE_INTERNAL_VOLATILE,            \
               .location = {                                             \
                  .slot =  SL_SE_KEY_SLOT_VOLATILE_0                     \
               }                                                         \
         }                                                               \
   }


typedef struct {
   bool is_active;
   bool is_secured;
   bool challenge_retrieved;
   bool next_msg_requires_elevated_auth;
   uint8_t IV[IV_SIZE];
   uint8_t dev_pubkey[PUBKEY_SIZE];
   uint8_t session_challenge[CHALLENGE_SIZE];
   certificate_slot_id_t session_identity;
} session_information_t;

static session_information_t session_info = {.is_active = false, .is_secured = false, .challenge_retrieved = false, .IV = {0}, .dev_pubkey = {0}, .session_challenge = {0}, .session_identity = NUM_CERTS_SLOTS, .next_msg_requires_elevated_auth = false};

bool secure_session_manager_start_session() {
   if (session_info.is_active) {
         return false;
   }
   session_info.is_active = true;
   return session_info.is_active;
}

void secure_session_manager_stop_session() {
   sl_se_command_context_t ctx;
   sl_se_key_descriptor_t aes_128_store_key_description = AES128_KEY_STORE_DESC;
   sl_se_delete_key(&ctx, &aes_128_store_key_description);
   session_info.is_active = false;
   session_info.is_secured = false;
   memset(session_info.session_challenge, 0, CHALLENGE_SIZE);
   session_info.challenge_retrieved = false;
   session_info.next_msg_requires_elevated_auth = false;
   session_info.session_identity = NUM_CERTS_SLOTS;
}

bool secure_session_manager_get_dev_pubkey(secure_session_public_key_t* pubkey) {

   if (secure_session_manager_is_secured() &&
         pubkey->buffer_len >= PUBKEY_SIZE) {
         memcpy(pubkey->buffer, session_info.dev_pubkey, PUBKEY_SIZE);
         return true;
   }
   return false;
}

bool secure_session_manager_is_started() {
   return session_info.is_active;
}

bool secure_session_manager_is_secured() {
   return session_info.is_secured;
}

bool secure_session_manager_set_client_pubkey(secure_session_public_key_t* pubkey) {


   if (pubkey->buffer_len < PUBKEY_SIZE ||
         !secure_session_manager_is_started()) {
       pubkey->buffer[0] = 0x01;
         return false;
   }

   bool secure_session_established = false;
   sl_se_command_context_t ctx;

   uint8_t session_keypair[PRIVKEY_SIZE + PUBKEY_SIZE] = {0};
   uint8_t session_shared_secret_buffer[SHAREDKEY_SIZE] = {0};
   sl_se_key_descriptor_t session_keypair_description = GENERATED_KEY_DESC;
   session_keypair_description.storage.location.buffer.pointer = session_keypair;

   if (sl_se_generate_key(&ctx, &session_keypair_description) == SL_STATUS_OK) {

      sl_se_key_descriptor_t client_pubkey_description = PUB_KEY_DESC;
      client_pubkey_description.storage.location.buffer.pointer = pubkey->buffer;
      sl_se_key_descriptor_t session_shared_key_description = SHARED_KEY_DESC;
      session_shared_key_description.storage.location.buffer.pointer = session_shared_secret_buffer;


      if(sl_se_ecdh_compute_shared_secret(&ctx, &session_keypair_description, &client_pubkey_description, &session_shared_key_description) == SL_STATUS_OK) {

            memcpy(session_info.IV, session_shared_key_description.storage.location.buffer.pointer, IV_PART_1_SIZE);
            memcpy(session_info.IV + IV_PART_1_SIZE, session_shared_key_description.storage.location.buffer.pointer + IV_PART_2_START, IV_PART_2_SIZE);


            sl_se_key_descriptor_t aes_128_input_key_description = AES128_KEY_IN_DESC;
            aes_128_input_key_description.storage.location.buffer.pointer = session_shared_key_description.storage.location.buffer.pointer + AES_KEY_START;

            sl_se_key_descriptor_t aes_128_store_key_description = AES128_KEY_STORE_DESC;
            secure_session_established = sl_se_import_key(&ctx, &aes_128_input_key_description, &aes_128_store_key_description) == SL_STATUS_OK;
            session_info.is_secured = secure_session_established;
            if (session_info.is_secured) {
                sl_se_key_descriptor_t pubkey_description = {
                    .type = SL_SE_KEY_TYPE_ECC_P256,
                    .flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY,
                    .storage = {
                        .location = {
                            .buffer = {
                                .pointer = session_info.dev_pubkey,
                                .size = PUBKEY_SIZE
                            }
                        }
                    }
                };
                if (sl_se_export_public_key(&ctx, &session_keypair_description, &pubkey_description) != SL_STATUS_OK) {
                      secure_session_established = false;
                }
            }
      }

   }
   memset(session_keypair, 0, PRIVKEY_SIZE + PUBKEY_SIZE);
   memset(session_shared_secret_buffer, 0, SHAREDKEY_SIZE);

   return secure_session_established;
}

bool secure_session_manager_get_session_challenge(secure_session_challenge_t* challenge) {

   sl_se_command_context_t cmd_ctx;
   if (secure_session_manager_is_started() &&
         !session_info.challenge_retrieved &&
         sl_se_get_random(&cmd_ctx, session_info.session_challenge, CHALLENGE_SIZE) == SL_STATUS_OK) {
            
         memcpy(challenge->buffer, session_info.session_challenge, CHALLENGE_SIZE);
         session_info.challenge_retrieved = true;
         return true;
   }
   return false;
}

bool secure_session_manager_verify_session_challenge_response(secure_session_challenge_t* challenge_response) {

   if (challenge_response->buffer_len >= SIGNATURE_SIZE && identity_authentication_verify(session_info.session_identity, session_info.session_challenge, CHALLENGE_SIZE, challenge_response->buffer, challenge_response->buffer_len)) {

         return true;
   }
   secure_session_manager_stop_session();
   return false;

}

static uint8_t calculate_extra_padding_length(size_t msg_size) {
   uint8_t extra_padding_length = CIPHER_BLOCK_SIZE - (msg_size % CIPHER_BLOCK_SIZE);

   if (extra_padding_length == 0) {
         extra_padding_length = CIPHER_BLOCK_SIZE;
   }
   return extra_padding_length;
}


size_t secure_session_manager_encrypt_msg(uint8_t* msg, size_t msg_size, uint8_t* encrypted_msg, size_t max_encrypted_msg_size) {

   if (msg == NULL || encrypted_msg == NULL || !secure_session_manager_is_secured()) {
         return 0;
   }

   sl_se_command_context_t cmd_ctx;
   sl_se_key_descriptor_t aes_128_store_key_description = AES128_KEY_STORE_DESC;

   size_t encrypted_size = 0;
   uint8_t extra_padding_length = calculate_extra_padding_length(msg_size);
   size_t padded_msg_size = msg_size + extra_padding_length;

   if (padded_msg_size <= max_encrypted_msg_size) {

      uint8_t padded_msg[padded_msg_size];
      memcpy(padded_msg, msg, msg_size);
      memset(padded_msg + msg_size, extra_padding_length, extra_padding_length);

      uint8_t tmp_iv[IV_SIZE];
      memcpy(tmp_iv, session_info.IV, IV_SIZE);
      if (sl_se_aes_crypt_cbc(&cmd_ctx, &aes_128_store_key_description, SL_SE_ENCRYPT, padded_msg_size, tmp_iv, padded_msg, encrypted_msg) == SL_STATUS_OK) {
         encrypted_size = padded_msg_size;
      }
   }

   return encrypted_size;

}

size_t secure_session_manager_decrypt_msg(uint8_t* encrypted_msg, size_t encrytped_msg_size, uint8_t* msg, size_t max_msg_size) {

   if (encrypted_msg == NULL || msg == NULL || !secure_session_manager_is_secured()) {
         return 0;
   }

   sl_se_command_context_t cmd_ctx;
   sl_se_key_descriptor_t aes_128_store_key_description = AES128_KEY_STORE_DESC;
   uint8_t decrypted_tmp[encrytped_msg_size];
   size_t decrypted_msg_size = 0;
   uint8_t tmp_iv[IV_SIZE];
   memcpy(tmp_iv, session_info.IV, IV_SIZE);
   if (sl_se_aes_crypt_cbc(&cmd_ctx, &aes_128_store_key_description, SL_SE_DECRYPT, encrytped_msg_size, tmp_iv, encrypted_msg, decrypted_tmp) == SL_STATUS_OK) {
         size_t padding_count =  decrypted_tmp[encrytped_msg_size - 1];
         size_t calculated_decrypted_msg_size = encrytped_msg_size - padding_count;
         if (calculated_decrypted_msg_size <= max_msg_size) {
               decrypted_msg_size = calculated_decrypted_msg_size;
               memcpy(msg, decrypted_tmp, encrytped_msg_size - padding_count);
         }
   }

   return decrypted_msg_size;
}

certificate_slot_id_t secure_session_manager_get_session_identity() {
   return session_info.session_identity;
}

void secure_session_manager_set_session_identity(certificate_slot_id_t session_identity) {
   session_info.session_identity = session_identity;
}

