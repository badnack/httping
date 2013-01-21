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

#include <arpa/inet.h>
#ifndef NO_SSL
#include <openssl/ssl.h>
#include "mssl.h"
#endif
#include "handler.h"

typedef struct host_param host_param;
struct host_param {
  int ok, err;
  int partial_write, partial_read;
  int Bps_min, Bps_max, Bps;
  long long int Bps_avg;
  double avg, min, max;
  double avg_httping_time;
  double dl_start, dl_end;  
  int curncount;
  int cur_limit;
  char* name;
  char *sc;
  char persistent_did_reconnect;
  int portnr;
  char use_ssl;
  char have_resolved;
  double dstart, dend, wait;
  struct sockaddr_in6 addr;
  ping_handler ph; //FIXME, void?
  int fatal;
  int persistent_tries;
  char* header;
  int header_len;
  long long int bytes_transferred;
#ifndef NO_SSL
  SSL_CTX *client_ctx;
#endif
  SSL *ssl_h;
};

void hp_set_start_values(host_param* hp);
int hp_max_fd(host_param *hp, int n);
