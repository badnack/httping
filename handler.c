#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "handler.h"
#include "buffer.h"
#include "gen.h"

extern char last_error[];

int ph_init(ping_handler *ph, int s_size, int r_size)
{
  if (ph == NULL)
    return -1;

  ph->state = 0;
  ph->fd = -1;
  ph->i_req_pnt = ph->i_req_cnt = 0;
  ph->reply = ph->request = NULL;

  if ((s_size > 0) && (ph->reply = (ping_buffer*) pb_create(s_size)) == NULL)
    return -1;
  if ((r_size > 0) && (ph->request = (ping_buffer*) pb_create(r_size)) == NULL)
    return -1;

  return 0;
}

void ph_free(ping_handler *ph)
{
  if (ph == NULL)
    return;
  if (ph->reply != NULL)
      free(ph->reply);
  if (ph->request != NULL)
      free(ph->request);
}

int ph_write(ping_handler* ph)
{
  int rc;

  if (ph == NULL)
    return -1;

  rc = pb_socket_send(((ping_buffer*)ph->request), ph->fd);

  if (rc == -1)
    snprintf(last_error, ERROR_BUFFER_SIZE, "ph_write::write failed: %s\n", strerror(errno));
  else if (rc == -2)
    snprintf(last_error, ERROR_BUFFER_SIZE, "connection prematurely closed by peer\n");
  else /* succesfully transferred bytes */
    {
      if (((ping_buffer*)ph->request)->cnt <= 0)
        {
          ((ping_buffer*)ph->request)->pnt = ph->i_req_pnt; /* the request is always the same */
          ((ping_buffer*)ph->request)->cnt = ph->i_req_cnt;
          rc = 1;
        }
      else
        rc = 0;
    }

  return rc;
}

int ph_write_ssl(SSL* ssl_h, ping_handler* ph)
{
  int rc;

  if (ph == NULL)
    return -1;

  rc = pb_ssl_send(((ping_buffer*)ph->request), ssl_h);

  if (rc == -1)
    snprintf(last_error, ERROR_BUFFER_SIZE, "ph_write::write failed: %s\n", strerror(errno));
  else if (rc == -2)
    snprintf(last_error, ERROR_BUFFER_SIZE, "connection prematurely closed by peer\n");
  else /* succesfully transferred bytes */
    {
      if (((ping_buffer*)ph->request)->cnt <= 0)
        {
          ((ping_buffer*)ph->request)->pnt = ph->i_req_pnt; /* the request is always the same */
          ((ping_buffer*)ph->request)->cnt = ph->i_req_cnt;
          rc = 1;
        }
      else
        rc = 0;
    }

  return rc;
}

int ph_read_HTTP_header(ping_handler* ph, char** header, int* h_len/* , int* overflow */)
{
  int rc;

  /* #ifndef NO_SSL */
  /*    if (ssl_h) */
  /*      rrc = SSL_read(ssl_h, &buffer[len_in], now_n); */
  /*    else */
  /* #endif */
  rc = pb_socket_recv(ph->reply, ph->fd);
  if (rc == 0 || rc == -1)	/* socket closed before request was read? */
    return -1;

  pb_read(ph->reply, header, *h_len);
  *h_len = strlen(*header);

  if (strstr(*header, "\r\n\r\n") != NULL)
    return 1;


  /* char *term = strstr(buffer, "\r\n\r\n"); */
  /* if (term) */
  /*  *overflow = len_in - (term - buffer + 4); */
  /* else */
  /*  *overflow = 0; */

  return 0;
}

int ph_read(ping_handler* ph)
{
  if (ph == NULL)
    return -1;
  return 0;
}
