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
#include <openssl/ssl.h>

#define FMT_SIZE 512
#define MAX_SEND 512
#define MAX_RECV 512

typedef struct _buffer _buffer;
typedef struct ping_buffer ping_buffer;

struct _buffer{
  int size;
  int available;
  int pnt;
  int full;
  int cnt;
  char buf[0];
};

struct ping_buffer{
  _buffer* request;
  _buffer* reply;
};

int pb_init(ping_buffer* pb, int req_size, int rep_size);
void pb_free(ping_buffer* pb);
int pb_write_request(ping_buffer* pb, int mode, char* fmt, ...);
int pb_read_reply(ping_buffer* pb, char* buffer, int n);
int pb_socket_send_request(ping_buffer* pb, int sd);
int pb_ssl_send_request(ping_buffer* pb, SSL* ssl_h);
int pb_socket_recv_reply(ping_buffer* pb, int sd);
int pb_ssl_recv_reply(ping_buffer* pb, SSL* ssl_h);
int pb_get_cnt_reply(ping_buffer* pb);
int pb_get_cnt_request(ping_buffer* pb);
