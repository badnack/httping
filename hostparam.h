#include <arpa/inet.h>
#ifndef NO_SSL
#include <openssl/ssl.h>
#include "mssl.h"
#endif
#include "handler.h"


typedef struct host_param host_param;
struct host_param{
  int ok, err;
  int partial_write, partial_read;
  int Bps_min, Bps_max;
  long long int Bps_avg;
  double avg, min, max;
  double avg_httping_time;
  int curncount;
  char* name;
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
#ifndef NO_SSL
  SSL_CTX *client_ctx;
#endif
  SSL *ssl_h;
};

int max_fd(host_param *hp, int n);
