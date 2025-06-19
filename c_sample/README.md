# Secure Communication Service

This sample code is taken from an smart lock implementation I wrote. 

The secure_communications_service is intended to manage the ECDH key exchange protocol with a client device. The overall design of the firmware is event driven, so from a usage perspective, calling the init function registers the event handler with the simple message dispatcher event loop. Any messages received by the bluetooth service over the Secure Communication Exchange characteristics are routed to and from this service. 

Throughout the key exchange process, the secure_session_manager is used to perform the cryptographic operations and maintain the current secure session information. 

The functions found in secure_session_manager_internal.h are used solely by the secure_communication_service to manage the current secure session or key exchange. 

The functions found in secure_session_manager.h file are used by the bluetooth service in order to enforce secure communication over the bluetooth charactersistcs that are configured as "secured".  

The ```msg_handler``` function is event handler for the component and is where the main logic is located. 

```msg_dispatcher_dispatch``` is used to send a message back to the client device via the bluetooth service.
```dispatch_msgs``` is used to send a list of messages back to the client in sequence. This is used to make it easy to send multi-payload messages that are too big for a single bluetooth message.

```identity_authentication_*``` functions are from another component that uses MBed-TLS for certificate based verification and signing. 

```sl_*``` functions are provided by the board vendor, Silicon Labs. ```sl_se_*``` functions are specific to the board Secure Element functions.