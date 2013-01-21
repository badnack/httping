
#ifndef STATES_INCLUDE
#define STATES_INCLUDE

#include "hostparam.h"

enum{
  CONT_LEN_FAIL = -6,
  PART_READ     = -5,
  PART_WRITE    = -4,
  PERS_FAIL     = -3,
  N_PERS_FAIL   = -2,
  RECV_FAIL     = -1,
  REQUEST_SENT  =  1,
  REPLY_RECV    =  1,
  BODY_RECV     =  1
};

inline int state_write(host_param* hp_tmp, int req_sent, int persistent_connections, int* n_partial_write, int use_ssl);
inline int state_read_header(host_param* hp_tmp, int persistent_connections, int* n_partial_read, int show_statuscodes, int machine_readable, int ask_compression, char* is_compressed, int show_bytes_xfer);
inline int state_read_body(host_param* hp_tmp, int Bps_limit);

#endif
