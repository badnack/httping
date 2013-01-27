/* The GPL applies to this program.
   In addition, as a special exception, the copyright holders give
   permission to link the code of portions of this program with the
   OpenSSL library under certain conditions as described in each
   individual source file, and distribute linked combinations
   including the two.
   You must obey the GNU General Public License in all respects
   for all of the code used other than OpenSSL.  If you modify
   file(s) with this exception, you may extend this exception to your
   version of the file(s), but you are not obligated to do so.  If you
   do not wish to do so, delete this exception statement from your
   version.  If you delete this exception statement from all source
   files in the program, then also delete it here.
*/

#ifndef HANDLER_INCLUDE
#define HANDLER_INCLUDE

#include <openssl/ssl.h>
#include "buffer.h"

/** ping_handler definition */
typedef struct ping_handler ping_handler;

/**  ping_handler structure */
struct ping_handler {
  /** it represents the machine state in wich the pinged host is */
  int state;
  /** file descriptor (socket would be more correct) used to ping the host */
  int fd;
  /** ping buffer */
  ping_buffer pb;
};

/**
   Initilalizes the handler.

   @param ph Ping handler structure
   @param s_size Size of transmission buffer
   @param r_size Size of reply buffer
   @return zero on success, @c -1 if the an error occurred
*/
int ph_init(ping_handler *ph, int s_size, int r_size);

/**
   Frees a handler structure.

   @param ph Ping handler structure

*/
void ph_free(ping_handler *ph);

/**
   Sends a request to the pinged host.

   @param ph Ping handler structure
   @return @c 1 if the request is completely sent, @c 0 if just a part of the request has been sent
   (in this case at least another ph_send is required); @c -1 if an error occurred.
*/
int ph_send(ping_handler* ph);

/**
   Sends a request to the pinged host via SSL.

   @param ph Ping handler structure
   @return @c 1 if the request is completely sent, @c 0 if just a part of the request has been sent
   (in this case at least another ph_send is required); @c -1 if an error occurred.
*/
int ph_send_ssl(SSL* ssl_h, ping_handler* ph);

/**
   Receives the HTTP header from a pinged host.

   @param ph Ping handler structure
   @param header Pointer to a buffer to store the hedaer
   @param h_len Pointer to an integer to store the header length
   @param overflow Pointer to an integer in order to store the heade overflow if a part of body has been received
   @return @c 1 if the request is completely sent, @c 0 if just a part of the request has been sent
   (in this case at least another ph_send is required); @c -1 if an error occurred.
*/
int ph_recv_HTTP_header(ping_handler* ph, char** header, int* h_len, int* overflow);

/**
   Receives the HTTP header from a pinged host, and stores it in the reply buffer.

   @param ph Ping handler structure
   @param header Pointer to a buffer to store the hedaer
   @param h_len Pointer to an integer to store the header length
   @param overflow Pointer to an integer in order to store the heade overflow if a part of body has been received
   @return @c 1 if the request is completely sent, @c 0 if just a part of the request has been sent
   (in this case at least another ph_send is required); @c -1 if an error occurred.
*/
int ph_recv_ssl_HTTP_header(ping_handler* ph, SSL* ssl_h, char** header, int* h_len, int* overflow);

/**
   Receives the HTTP body from a pinged host, and stores it in the reply buffer.


   @param ph Ping handler structure
   @param body Pointer to a buffer to store the hedaer
   @param b_len Pointer to an integer to store the header length
   @return @c 1 if the request is completely sent, @c 0 if just a part of the request has been sent
   (in this case at least another ph_send is required); @c -1 if an error occurred.
*/
int ph_recv_HTTP_body(ping_handler* ph, char** body, int* b_len);

/**
   Function used just to get the body and to remove it from memory.
   The HTTP body is used just to calculate the needed time to retrieve it in order to get
   the ping time.

   @param ph Ping handler structure
   @return the read bytes
*/
int ph_get_and_clean(ping_handler* ph);

#endif
