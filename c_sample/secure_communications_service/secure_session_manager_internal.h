
#ifndef SECURE_SESSION_MANAGER_INTERNAL_H
#define SECURE_SESSION_MANAGER_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif 

#include "stdint.h"
#include "stddef.h"
#include "common_helpers.h"

typedef generic_buffer_structure_t secure_session_public_key_t;
typedef generic_buffer_structure_t secure_session_challenge_t;


   bool secure_session_manager_start_session();
   bool secure_session_manager_get_dev_pubkey(secure_session_public_key_t* pubkey);
   bool secure_session_manager_set_client_pubkey(secure_session_public_key_t* pubkey);
   bool secure_session_manager_get_session_challenge(secure_session_challenge_t* challenge);
   bool secure_session_manager_verify_session_challenge_response(secure_session_challenge_t* challenge_response);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_SESSION_MANAGER_INTERNAL_H */
