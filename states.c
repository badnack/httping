#include <unistd.h>

#include "states.h"
#include "utils.h"
#include "handler.h"
#include "hostparam.h"
#include "gen.h"
#include "res.h"
#include "tcp.h"
#include "io.h"


extern void emit_error();
extern char* last_error;

inline int state_init(host_param* hp_tmp, int resolve_once, struct addrinfo *ai, struct sockaddr_in* bind_to, char* proxyhost, int proxyport, char use_ipv6, int* req_sent, int persistent_connections, int timeout, int tfo)
{
  int port, rc;
  char* host;
  struct addrinfo* ai_use;

  host = proxyhost ? proxyhost : hp_tmp->name;
  port = proxyhost ? proxyport : hp_tmp->portnr;

  if (hp_tmp->ph.fd == -1 && (!resolve_once || (resolve_once == 1 && hp_tmp->have_resolved == 0)))
    {
      memset(&hp_tmp->addr, 0x00, sizeof(hp_tmp->addr));

      if (ai)
        {
          freeaddrinfo(ai);
          ai = NULL;
        }

      if (resolve_host(host, &ai, use_ipv6, port) == -1)
        {
          hp_tmp->err++;
          emit_error();
          hp_tmp->have_resolved = 1;
          return NOT_RESOLVED;
        }
      ai_use = select_resolved_host(ai, use_ipv6);
      get_addr(ai_use, &hp_tmp->addr);
    }

  *req_sent = 0;

  if ((persistent_connections && hp_tmp->ph.fd < 0) || (!persistent_connections))
    {
      hp_tmp->dstart = get_ts();
      hp_tmp->ph.fd = connect_to((struct sockaddr *)bind_to, ai, timeout, tfo, &hp_tmp->ph.pb, req_sent);
    }

  if (hp_tmp->ph.fd == -3)
    return SOCKET_ERROR;

  if (hp_tmp->ph.fd < 0)
    {
      emit_error();
      hp_tmp->ph.fd = -1;
      return SOCKET_ERROR;
    }

  if (hp_tmp->ph.fd >= 0)
    {
      /* set socket to low latency */
      if (set_tcp_low_latency(hp_tmp->ph.fd) == -1)
        {
          close(hp_tmp->ph.fd);
          hp_tmp->ph.fd = -1;
          return SOCKET_ERROR;
        }

      /* set fd blocking */
      if (set_fd_blocking(hp_tmp->ph.fd) == -1)
        {
          close(hp_tmp->ph.fd);
          hp_tmp->ph.fd = -1;
          return SOCKET_ERROR;
        }

#ifndef NO_SSL
      if (hp_tmp->use_ssl && hp_tmp->ssl_h == NULL)
        {
          BIO *s_bio = NULL;
          rc = connect_ssl(hp_tmp->ph.fd, hp_tmp->client_ctx, &hp_tmp->ssl_h, &s_bio, timeout);
          if (rc != 0)
            {
              close(hp_tmp->ph.fd);
              hp_tmp->ph.fd = rc;

              if (persistent_connections)
                {
                  if (++hp_tmp->persistent_tries < 2)
                    {
                      close(hp_tmp->ph.fd);
                      hp_tmp->ph.fd = -1;
                      hp_tmp->persistent_did_reconnect = 1;
                      return PERS_FAIL;
                    }
                }
            }
        }
#endif
      hp_tmp->ph.state = (*req_sent) ? 2 : 1;
    }

  if (hp_tmp->ph.fd < 0)
    {
      if (hp_tmp->ph.fd == -2)
        snprintf(last_error, ERROR_BUFFER_SIZE, "timeout connecting to host\n");
      emit_error();
      hp_tmp->ph.state = 0;
      hp_tmp->ph.fd = -1;
      return SOCKET_ERROR;
    }

  return OK;
}

inline int state_write(host_param* hp_tmp, int req_sent, int persistent_connections)
{
  int rc;

#ifndef NO_SSL
  if (hp_tmp->use_ssl)
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
  int overflow;
  int rc, len;
  char* reply;

  len = overflow = 0;

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
          if (hp_tmp->sc != NULL)
            free(hp_tmp->sc);
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
      if (encoding && hp_tmp->sc != NULL)
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
