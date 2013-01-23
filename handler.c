#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "handler.h"
#include "gen.h"

extern char last_error[];

int ph_init(ping_handler *ph, int s_size, int r_size)
{
  if (ph == NULL || s_size <= 0 || r_size <= 0)
    return -1;

  ph->state = 0;
  ph->fd = -1;

  return pb_init(&ph->pb, s_size, r_size);
}

void ph_free(ping_handler *ph)
{
  if (ph == NULL)
    return;
  pb_free(&ph->pb);
}

int ph_send(ping_handler* ph) //FIXME: return length written
{
  int rc;

  if (ph == NULL)
    return -1;

  rc = pb_socket_send_request(&ph->pb, ph->fd);
  if (rc == -1)
    snprintf(last_error, ERROR_BUFFER_SIZE, "ph_send::write failed: %s\n", strerror(errno));
  else if (rc == -2)
    snprintf(last_error, ERROR_BUFFER_SIZE, "connection prematurely closed by peer\n");
  else if (rc > 0 && ph->pb.request->pnt == 0) //the whole request has been sent
    return 1;

  return 0;
}

int ph_send_ssl(SSL* ssl_h, ping_handler* ph)
{
  int rc;

  if (ph == NULL)
    return -1;

  rc = pb_ssl_send_request(&ph->pb, ssl_h);

  if (rc == -1)
    snprintf(last_error, ERROR_BUFFER_SIZE, "ph_send_ssl::write failed: %s\n", strerror(errno));
  else if (rc == -2)
    snprintf(last_error, ERROR_BUFFER_SIZE, "connection prematurely closed by peer\n");
  else if (rc > 0 && ph->pb.request->pnt == 0) //the whole request has been sent
    return 1;
  return 0;
}

int ph_recv_HTTP_header(ping_handler* ph, char** header, int* h_len, int* overflow)
{
  int rc, ret, cnt;
  char* term;

  rc = pb_socket_recv_reply(&ph->pb, ph->fd);
  if (rc == -1)	/* socket closed before request was reaad? */
    return -1;

  if (*h_len < 0)
    *h_len = 0;

  *header = realloc(*header, *h_len + (cnt = pb_get_cnt_reply(&ph->pb)) + 1);
  ret = pb_read_reply(&ph->pb, *header + *h_len, cnt);
  *h_len += ret;
  (*header)[*h_len] = '\0';

  if ((term = strstr(*header, "\r\n\r\n")) != NULL)
    {
      *overflow = *h_len - (term - *header + 4);
      return 1;
    }

  *overflow = 0;

  return 0;
}

int ph_recv_ssl_HTTP_header(ping_handler* ph, SSL* ssl_h, char** header, int* h_len, int* overflow)
{
  int rc, ret, cnt;
  char* term;

  rc = pb_ssl_recv_reply(&ph->pb, ssl_h);

  if (rc == -1)	/* socket closed before request was read? */
    return -1;

  if (*h_len < 0)
    *h_len = 0;

  *header = (char*)realloc(*header, *h_len + (cnt = pb_get_cnt_reply(&ph->pb)) + 1);
  ret = pb_read_reply(&ph->pb, *header + *h_len, cnt);
  *h_len += ret;
  (*header)[*h_len] = '\0';

  if ((term = strstr(*header, "\r\n\r\n")) != NULL)
    {
      *overflow = *h_len - (term - *header + 4);
      return 1;
    }

  *overflow = 0;

  return 0;
}

int ph_recv_HTTP_body(ping_handler* ph, char** buffer)
{
  int rc, cnt;

  if (ph == NULL)
    return -1;
  rc = pb_socket_recv_reply(&ph->pb, ph->fd);

  if (rc == -1)	/* socket closed before request was read? */
    return -1;

  if (buffer != NULL && (cnt = pb_get_cnt_reply(&ph->pb)) > 0)
    {
      *buffer = (char*)realloc(*buffer, cnt);
      cnt = pb_read_reply(&ph->pb, *buffer, cnt);
    }

  return cnt;
}

int ph_get_and_clean(ping_handler* ph)
{
  char* dummy = NULL;
  int rc;

  rc = ph_recv_HTTP_body(ph, &dummy);
  if (dummy != NULL) //in order to empty the ping_buffer
    free(dummy);
  return rc;
}
