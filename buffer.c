#include "buffer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int awrite(ping_buffer* pb, char* buf, int buf_len)
{
  int to_write;
  int w_pnt, len;

  if (pb == NULL)
    return -1;

  len = buf_len;

  while (buf_len > 0)
    {
      w_pnt = pb->available;
      to_write = pb->size - pb->cnt;
      if (to_write == 0)
        break;
      to_write = (to_write > buf_len) ? buf_len : to_write;
      memmove(pb->buf + w_pnt, buf, to_write);
      pb->available = (pb->available + to_write) % pb->size;
      buf_len -= to_write;
      pb->cnt += to_write;
    }

  return len - buf_len;
}

ping_buffer* pb_create(int size)
{
  ping_buffer* pb;

  if ((pb = (ping_buffer*) malloc(sizeof (ping_buffer) + (sizeof (char) * size))) == NULL)
    return NULL;

  memset(pb, 0, sizeof (ping_buffer) + (sizeof (char) * size));
  pb->size = size;
  pb->available = 0;
  pb->pnt = 0;
  pb->cnt = 0;

  return pb;
}

int pb_write(ping_buffer* pb, char* fmt, ...)
{
  char formatted_string[FMT_SIZE];
  va_list argptr;
  int len;

  if (pb == NULL)
    return 0;

  va_start(argptr,fmt);
  vsnprintf(formatted_string, FMT_SIZE, fmt, argptr);
  va_end(argptr);
  len = strnlen(formatted_string, FMT_SIZE);

  return awrite(pb, formatted_string, len);
}

int pb_socket_send(ping_buffer* pb, int sd)
{
  ssize_t rc;
  int to_snd;

  if (pb == NULL)
    return -1;
  if (pb->cnt == 0)
    return 1;

  to_snd = (pb->available > pb->pnt) ? (pb->available - pb->pnt) : pb->size - pb->pnt;
  to_snd = (to_snd > MAX_SEND) ? MAX_SEND : to_snd;
  rc = write(sd, (char*)pb->buf + pb->pnt, to_snd);

  if (rc == -1)
    return -1;
  if (rc == 0)
    return -2;

  pb->pnt =  (pb->pnt + rc) % pb->size;
  pb->cnt -= rc;

  return rc;
}

int pb_ssl_send(ping_buffer* pb, SSL* ssl_h)
{
  ssize_t rc;
  int to_snd;

  if (pb == NULL || ssl_h == NULL)
    return -1;
  if (pb->cnt == 0)
    return 1;

  to_snd = (pb->available > pb->pnt) ? (pb->available - pb->pnt) : pb->size - pb->pnt;
  to_snd = (to_snd > MAX_SEND) ? MAX_SEND : to_snd;
  rc = SSL_write(ssl_h, (char*)pb->buf + pb->pnt, to_snd);

  if (rc == -1)
    return -1;
  if (rc == 0)
    return -2;


  pb->pnt =  (pb->pnt + rc) % pb->size;
  pb->cnt -= rc;

  return rc;
}

/* int pb_socket_recv(ping_buffer* pb, int sd) */
/* { */
  /* int rc; */
  /* int to_recv; */

  /* if (pb == NULL) */
  /*   return -1; */

  /* to_recv = ((pb->size - pb->available) > MAX_RECV) ? MAX_RECV : (pb->size - pb->available); */
  /* if (rc = read(sd, (char*)pb->buf + pb->pnt, to_recv) < 0) */
  /*   { */
  /*     pb->pnt = 0; //see man 2 read */
  /*     return -1; */
  /*   } */

  /* pb->available = (pb->available + rc) % pb->size; */

  /* return rc;   */
/* } */

/* int pb_ssl_recv(ping_buffer* pb, SSL* ssl_h) */
/* {} */
