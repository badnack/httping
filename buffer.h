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

#ifndef BUFFER_INCLUDE
#define BUFFER_INCLUDE

#include <openssl/ssl.h>

/** Maximum forma size */
#define FMT_SIZE 512
/** Maximum send length */
#define MAX_SEND 512
/** Maximum recv length */
#define MAX_RECV 512

typedef struct _buffer _buffer;
typedef struct ping_buffer ping_buffer;

/**
   Buffer structure.
*/
struct _buffer{
  /** buffer size */
  int size;
  /** available bits */
  int available;
  /** pointer to current position */
  int pnt;
  /** amount of space used */
  int cnt;
  /** hack struct buffer*/
  char buf[0];
};

/**
   Buffers to manage multi-host ping.
   The first is a regular buffer since the request length must to be well-known.
   The second one is a circular buffer because HTTP headers (or web pages)
   may have different lengths.
*/
struct ping_buffer{
  /** regularbuffer */
  _buffer* request;
  /** circular buffer */
  _buffer* reply;
};

/**
   Initializes a ping_buffer structure.
   
   @param pb Ping buffer structure
   @param req_size Size of request buffer
   @param rep_size Size of reply buffer
   @return zero on success, @c -1 if an error occurred

*/
int pb_init(ping_buffer* pb, int req_size, int rep_size);

/**
   Frees a ping buffer structure.

   @param pb Ping buffer structure
*/
void pb_free(ping_buffer* pb);

/**
   Writes a request in the request buffer.
   
   @param pb Ping buffer structure
   @param mode Write mode: @c 0 trunc, @c 1 append
   @param fmt An arbitrary list of strings
   @return number of written bytes, or @c -1 if an error occurred
*/
int pb_write_request(ping_buffer* pb, int mode, char* fmt, ...);

/**
   Retrieves n bytes from the reply buffer.
   
   @param pb Ping buffer structure
   @param buffer A buffer to store the reply bytes
   @param n Amount of bytes to get
   @return number of read bytes, or @c -1 if an error occurred
*/
int pb_read_reply(ping_buffer* pb, char* buffer, int n);

/**
   Retrieves n bytes from the request buffer.
   
   @param pb Ping buffer structure
   @param buffer A buffer to store the request bytes
   @param n Amount of bytes to get
   @return number of read bytes, or @c -1 if an error occurred
*/
int pb_read_request(ping_buffer* pb, char* buffer, int n);

/**
   Send the request buffer content (or a part of it) over a socket.

   @param pb Ping buffer structure
   @param sd Socket descriptor
   @return Number of bytes sent, or @c -1 if an error occurred
*/
int pb_socket_send_request(ping_buffer* pb, int sd);

/**
   Send the request buffer content (or a part of it) over a SSL channel.

   @param pb Ping buffer structure
   @param ssl_h SSL channel
   @return number of bytes sent, or @c -1 if an error occurred
*/
int pb_ssl_send_request(ping_buffer* pb, SSL* ssl_h);

/**
   Retrieves a HTTP reply from a socket.

   @param pb Ping buffer structure
   @param sd Socket descriptor
   @return number of nytes read, or @c -1 if an error occurred
*/
int pb_socket_recv_reply(ping_buffer* pb, int sd);

/**
   Retrieves a HTTP reply from a SSL channel.

   @param pb Ping buffer structure
   @param ssl_h SSL channel
   @return number of nytes read, or @c -1 if an error occurred   
*/
int pb_ssl_recv_reply(ping_buffer* pb, SSL* ssl_h);

/**
   Retrieves the amount (in bytes) of the HTTP reply.

   @param pb Ping buffer structure
   @return amount of reply bytes, or @c -1 if an error occurred
*/
int pb_get_cnt_reply(ping_buffer* pb);

/**
   Retrieves the amount (in bytes) of the HTTP request.

   @param pb Ping buffer structure
   @return amount of request bytes, or @c -1 if an error occurred
*/
int pb_get_cnt_request(ping_buffer* pb);

#endif
