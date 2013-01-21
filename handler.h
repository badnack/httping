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
#include "buffer.h"

typedef struct ping_handler ping_handler;

struct ping_handler {
  int state;
  int fd;
  ping_buffer pb;
};

int ph_init(ping_handler *ph, int s_size, int r_size);
void ph_free(ping_handler *ph);
int ph_read(ping_handler* ph);
int ph_send(ping_handler* ph);
int ph_send_ssl(SSL* ssl_h, ping_handler* ph);
int ph_recv_HTTP_header(ping_handler* ph, char** header, int* h_len, int* overflow);
int ph_recv_ssl_HTTP_header(ping_handler* ph, SSL* ssl_h, char** header, int* h_len, int* overflow);
int ph_recv_HTTP(ping_handler* ph);
int ph_recv_and_clean(ping_handler* ph);
