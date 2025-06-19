

#ifndef SECURE_COMMUNICATIONS_SERVICE_H
#define SECURE_COMMUNICATIONS_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "msg_dispatcher.h"

#define ECDH_MSG_EXCHANGE_INBOUND_HANDLER_ID 0
#define ECDH_MSG_EXCHANGE_OUTBOUND_HANDLER_ID 1

   void secure_communications_service_init(msg_dispatcher_t* dispatcher);

#ifdef __cplusplus
}
#endif




#endif /* SECURE_COMMUNICATIONS_SERVICE_H */
