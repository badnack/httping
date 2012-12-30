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

#include "handler.h"
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct host_param host_param;

struct host_param{
  char* request;
  int req_len;
  char* name;
  char have_resolved;
  int error;
  double dstart, dend;
  struct sockaddr_in6 addr;
  ping_handler ph;
};

int hp_max_fd(host_param *hp, int n);