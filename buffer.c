#include "buffer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int awrite(ping_buffer* pb, char* buf, int len)
{
  int cnt, tot;
  int pnt;

  if (pb == NULL)
    return -1;

  pnt = pb->available;

  while (len > 0)
    {
      cnt = pb->size - pb->available;
      tot = snprintf(pb->buf + pnt, cnt, "%s", buf);
      pb->available = (pb->available + tot) % pb->size;
      pnt = (pnt + tot) % pb->size;
      len -= tot;
    }

  return len;
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

  return pb;
}

int pb_awrite(ping_buffer* pb, char* fmt, ...)
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
  pb->available = 0;
  pb->pnt = 0;

  return awrite(pb, formatted_string, len);
}

int pb_socket_send(ping_buffer* pb, int sd)
{
  ssize_t rc;
  int to_snd;
  
  to_snd = ((pb->available - pb->pnt) > MAX_SEND) ? MAX_SEND : (pb->available - pb->pnt);
  
  if (pb == NULL)
    return -1;

  rc = write(sd, (char*)pb->buf + pb->pnt, to_snd);

  if (rc == -1)
    return -1;
  if (rc == 0)
    return -2;

  pb->pnt += rc;
  if (pb->pnt == pb->available)
    {
      pb->pnt = 0;
      return 1;
    }

  return 0;
}

int pb_ssl_send(ping_buffer* pb, SSL* ssl_h)
{
  ssize_t rc;

  if (pb == NULL || ssl_h == NULL)
    return -1;

  rc = SSL_write(ssl_h, (char*)pb->buf + pb->pnt, pb->available);

  if (rc == -1)
    return -1;
  if (rc == 0)
    return -2;

  pb->pnt += rc;
  if (pb->pnt == pb->available)
    {
      pb->pnt = 0;
      return 1;
    }

  return 0;
}
