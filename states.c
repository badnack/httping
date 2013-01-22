#include <unistd.h>

#include "states.h"
#include "utils.h"
#include "handler.h"
#include "hostparam.h"
#include "gen.h"


extern void emit_error();
extern char* last_error;

inline int state_write(host_param* hp_tmp, int req_sent, int persistent_connections, int use_ssl)
{
  int rc;

#ifndef NO_SSL
  if (hp_tmp->use_ssl || use_ssl)
    rc = ph_send_ssl(hp_tmp->ssl_h, &hp_tmp->ph);
  else
#endif
    {
      if (!req_sent)
        {
          hp_tmp->dstart = get_ts();
          rc = ph_send(&hp_tmp->ph);
        }
      else
        rc = 1;
    }
  if (rc < 0) //errors
    {
      if (persistent_connections)
        {
          if (++hp_tmp->persistent_tries < 2)
            {
              close(hp_tmp->ph.fd);
              hp_tmp->persistent_did_reconnect = 1;
              hp_tmp->ph.fd = -1;
              hp_tmp->ph.state = 0;
              return PERS_FAIL; //try again!
            }
        }
      emit_error();
      close(hp_tmp->ph.fd);
      hp_tmp->ph.fd = -1;
      hp_tmp->ph.state = 0;
      hp_tmp->err++;
      return N_PERS_FAIL;
    }
  else if (rc == 0) //rc == 0: write not yet completed
    return PART_WRITE;

  return REQUEST_SENT;
}

inline int state_read_header(host_param* hp_tmp, int persistent_connections, int show_statuscodes, int machine_readable, int ask_compression, char* is_compressed, int show_bytes_xfer)
{
  int overflow = 0;
  int rc, len;
  char* reply;

#ifndef NO_SSL
  if (hp_tmp->ssl_h)
    rc = ph_recv_ssl_HTTP_header(&hp_tmp->ph, hp_tmp->ssl_h, &hp_tmp->header, &hp_tmp->header_len, &overflow); //FIXME
  else
#endif
    rc = ph_recv_HTTP_header(&hp_tmp->ph, &hp_tmp->header, &hp_tmp->header_len, &overflow); //FIXME

  if (rc < 0)
    {
      if (persistent_connections)
        {
          if (++hp_tmp->persistent_tries < 2)
            {
              close(hp_tmp->ph.fd);
              hp_tmp->ph.state = 0;
              hp_tmp->ph.fd = -1;
              hp_tmp->persistent_did_reconnect = 1;
              return PERS_FAIL;
            }
        }

      if (rc == -1)
        snprintf(last_error, ERROR_BUFFER_SIZE, "error receiving reply from host\n");

      emit_error();

      close(hp_tmp->ph.fd);
      hp_tmp->ph.fd = -1;
      hp_tmp->ph.state = 0;
      hp_tmp->err++;
      return RECV_FAIL;
    }

  if (rc == 0) // partial read performed
    return PART_READ;
  

  reply = hp_tmp->header;

  if ((show_statuscodes || machine_readable) && reply != NULL)
    {
      /* statuscode is in first line behind
       * 'HTTP/1.x'
       */
      char *dummy = strchr(reply, ' ');

      if (dummy)
        {
          hp_tmp->sc = strdup(dummy + 1);

          /* lines are normally terminated with a
           * CR/LF
           */
          dummy = strchr(hp_tmp->sc, '\r');
          if (dummy)
            *dummy = 0x00;
          dummy = strchr(hp_tmp->sc, '\n');
          if (dummy)
            *dummy = 0x00;
        }
    }

  if (ask_compression && reply != NULL)
    {
      char *encoding = strstr(reply, "\nContent-Encoding:");
      if (encoding)
        {
          char *dummy = strchr(encoding + 1, '\n');
          if (dummy) *dummy = 0x00;
          dummy = strchr(hp_tmp->sc, '\r');
          if (dummy) *dummy = 0x00;

          if (strstr(encoding, "gzip") == 0 || strstr(encoding, "deflate") == 0)
            {
              *is_compressed = 1;
            }
        }
    }

  if (persistent_connections && show_bytes_xfer && reply != NULL)
    {
      char *length = strstr(reply, "\nContent-Length:");
      if (!length)
        {
          snprintf(last_error, ERROR_BUFFER_SIZE, "'Content-Length'-header missing!\n");
          emit_error();
          close(hp_tmp->ph.fd);
          hp_tmp->ph.fd = -1;
          hp_tmp->ph.state = 0;
          return CONT_LEN_FAIL;
        }
      len = atoi(&length[17]);
    }

  if (reply != NULL)
    {
      hp_tmp->header_len = (strstr(reply, "\r\n\r\n") - reply) + 4;
      free(hp_tmp->header);
      hp_tmp->header = NULL;
      reply = NULL;
    }

  hp_tmp->dl_start = get_ts(); //Just before the state 3
  hp_tmp->bytes_transferred = 0;

  if (persistent_connections)
    {
      if (hp_tmp->cur_limit == -1 || len < hp_tmp->cur_limit)
        hp_tmp->cur_limit = len - overflow;
    }

  return REPLY_RECV;
}

inline int state_read_body(host_param* hp_tmp, int Bps_limit)
{
  int rc;
  static int recv = 0;

  hp_tmp->cur_limit = Bps_limit;
  rc = ph_recv_and_clean(&hp_tmp->ph);

  if (rc < 0)
    {
      close(hp_tmp->ph.fd);
      hp_tmp->ph.fd = -1;
      hp_tmp->ph.state = 0;
      return RECV_FAIL;
    }
  else if (rc > 0)
    {
      recv += rc;
      if (hp_tmp->cur_limit == -1 || (hp_tmp->cur_limit != -1 && hp_tmp->bytes_transferred < hp_tmp->cur_limit))
        return PART_READ;
    }

  hp_tmp->bytes_transferred = recv;
  hp_tmp->dl_end = get_ts();
  hp_tmp->Bps = hp_tmp->bytes_transferred / max(hp_tmp->dl_end - hp_tmp->dl_start, 0.000001);
  hp_tmp->Bps_min = min(hp_tmp->Bps_min, hp_tmp->Bps);
  hp_tmp->Bps_max = max(hp_tmp->Bps_max, hp_tmp->Bps);
  hp_tmp->Bps_avg += hp_tmp->Bps;
  recv = 0;

  return BODY_RECV;
}
