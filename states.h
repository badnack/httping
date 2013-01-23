
#ifndef STATES_INCLUDE
#define STATES_INCLUDE

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "hostparam.h"

enum{
  VALUE_NULL    =  8,
  NOT_RESOLVED  = -7,
  CONT_LEN_FAIL = -6,
  PART_READ     = -5,
  PART_WRITE    = -4,
  PERS_FAIL     = -3,
  N_PERS_FAIL   = -2,
  RECV_FAIL     = -1,
  SOCKET_ERROR  =  0,
  REQUEST_SENT  =  1,
  REPLY_RECV    =  1,
  BODY_RECV     =  1,
  OK            =  1,
};

inline int state_init(host_param* hp_tmp, int resolve_once, struct addrinfo *ai, struct sockaddr_in* bind_to, char* proxyhost, int proxyport, char use_ipv6, int* req_sent, char persistent_connections, int timeout, int tfo);
inline int state_write(host_param* hp_tmp, int req_sent, char persistent_connections);
inline int state_read_header(host_param* hp_tmp, char persistent_connections, int show_statuscodes, int machine_readable, int ask_compression, char* is_compressed, int show_bytes_xfer);
inline int state_read_body(host_param* hp_tmp, int Bps_limit);
inline state_show_results(host_param* hp_tmp, char persstent_connections, char show_fp, char machine_readable, char* ok_str, char show_statuscodes, int audible, int quiet, char nagios_mode, char show_Bps, char show_bytes_xfer, char ask_compression, char is_compressed, char* err_str, char split, double dafter_connect);

#endif
