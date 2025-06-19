
#ifndef SECURE_SESSION_MANAGER_H
#define SECURE_SESSION_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif 

#include <stdbool.h>
#include "sl_se_manager_types.h"
#include "certificate_entry.h"

   void secure_session_manager_stop_session();

   bool secure_session_manager_is_started();
   bool secure_session_manager_is_secured();

   void secure_session_manager_set_session_identity(certificate_slot_id_t session_identity);
   certificate_slot_id_t secure_session_manager_get_session_identity();

   size_t secure_session_manager_encrypt_msg(uint8_t* msg, size_t msg_size, uint8_t* encrypted_msg, size_t max_encrypted_msg_size);
   size_t secure_session_manager_decrypt_msg(uint8_t* encrypted_msg, size_t encrytped_msg_size, uint8_t* msg, size_t max_msg_size);





#ifdef __cplusplus
}
#endif

#endif /* SECURE_SESSION_MANAGER_H */
