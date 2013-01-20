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

  ph->data = ph->request = NULL;
  if ((s_size > 0) && (ph->data = (ping_buffer*) pb_create(s_size)) == NULL)
    return -1;
  if ((r_size > 0) && (ph->request = (ping_buffer*) pb_create(r_size)) == NULL)
    return -1;

  return 0;
}

void ph_free(ping_handler *ph)
{
  if (ph == NULL)
    return;
  if (ph->data != NULL)
      free(ph->data);
  if (ph->request != NULL)
      free(ph->request);
}

int ph_read(ping_handler* ph)
{
  if (ph == NULL)
    return -1;
  return 0;
}

int ph_write(ping_handler* ph)
{
  int rc;

  if (ph == NULL)
    return -1;

  rc = pb_socket_send(((ping_buffer*)ph->request), ph->fd);

  if (rc == -1)
    snprintf(last_error, ERROR_BUFFER_SIZE, "ph_write::write failed: %s\n", strerror(errno));
  if (rc == -2)
    snprintf(last_error, ERROR_BUFFER_SIZE, "connection prematurely closed by peer\n");

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
  if (rc == -2)
    snprintf(last_error, ERROR_BUFFER_SIZE, "connection prematurely closed by peer\n");

  return rc;
}
