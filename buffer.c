#include "buffer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int pb_read(_buffer* _buf, char* buffer, int n)
{
  int r_pnt, buf_pnt, ret;
  int to_read, tot_to_read;

  if (buffer == NULL || _buf == NULL)
    return -1;
  if (_buf->cnt == 0)
    return 0;

  r_pnt = _buf->pnt;
  buf_pnt = 0;
  tot_to_read = (_buf->cnt > n) ? n : _buf->cnt;
  ret = tot_to_read;

  while (tot_to_read > 0)
    {
      to_read = (_buf->pnt >= _buf->available) ? _buf->size - _buf->pnt : _buf->available - _buf->pnt;
      to_read = (tot_to_read > to_read) ? to_read : tot_to_read;
      memmove(buffer + buf_pnt, _buf->buf + r_pnt, to_read); //according man it should never fails
      _buf->pnt = (_buf->pnt + to_read) % _buf->size;
      r_pnt = _buf->pnt;
      buf_pnt += to_read;
      _buf->cnt -= to_read;
      tot_to_read -= to_read;
    }

  return ret;
}


int pb_init(ping_buffer* pb, int req_size, int rep_size)
{

  if (pb == NULL)
    return -1;

  pb->reply = pb->request = NULL;

  if ((pb->request = (_buffer*)malloc(sizeof(_buffer) + (sizeof (char) * req_size))) == NULL)
      return -1;
  if ((pb->reply = (_buffer*)malloc(sizeof(_buffer) + (sizeof (char) * rep_size))) == NULL)
    {
      free(pb->request);
      pb->request = NULL;
      return -1;
    }

  memset(pb->request, 0, sizeof (_buffer) + (sizeof (char) * req_size));
  memset(pb->reply, 0, sizeof (_buffer) + (sizeof (char) * rep_size));

  pb->request->size = req_size;
  pb->reply->size = rep_size;

  return 0;
}

void pb_free(ping_buffer* pb)
{
  if (pb == NULL)
    return;

  if (pb->reply != NULL)
    free(pb->reply);
  if (pb->request != NULL)
    free(pb->request);
}


int pb_write_request(ping_buffer* pb, int mode, char* fmt, ...)
{
  char formatted_string[FMT_SIZE];
  va_list argptr;
  int to_write;
  int w_pnt, len;
  _buffer* req;

  if (pb == NULL || (req = pb->request) == NULL)
    return -1;
  if (req->cnt == req->size && mode)
    return -1;

  va_start(argptr,fmt);
  vsnprintf(formatted_string, FMT_SIZE, fmt, argptr);
  va_end(argptr);
  len = strnlen(formatted_string, FMT_SIZE);

  if (!mode)
    req->pnt = req->available = req->cnt = 0;

  w_pnt = req->available;
  to_write = req->size - req->available;
  to_write = (to_write > len) ? len : to_write;
  memmove(req->buf + w_pnt, formatted_string, to_write); //according man it should never fails
  req->available = (req->available + to_write) % req->size;
  req->cnt += to_write;

  return to_write;
}

int pb_read_reply(ping_buffer* pb, char* buffer, int n)
{
  if (pb == NULL || buffer == NULL)
    return -1;
  return pb_read(pb->reply, buffer, n);
}

int pb_read_request(ping_buffer* pb, char* buffer, int n)
{
  if (pb == NULL || buffer == NULL)
    return -1;
  return pb_read(pb->request, buffer, n);
}

int pb_socket_send_request(ping_buffer* pb, int sd)
{
  ssize_t rc;
  int to_snd;
  _buffer* req;

  if (pb == NULL || (req = pb->request) == NULL || !req->cnt)
    return -1;

  to_snd = req->cnt - req->pnt;
  rc = write(sd, (char*)req->buf + req->pnt, to_snd);

  if (rc == -1)
    return -1;
  if (rc == 0)
    return -2;

  req->pnt = (req->pnt + rc) % req->cnt;

  return rc;
}

int pb_ssl_send_request(ping_buffer* pb, SSL* ssl_h)
{
  ssize_t rc;
  int to_snd;
  _buffer* req;

  if (pb == NULL || (req = pb->request) == NULL || !req->cnt)
    return -1;

  to_snd = req->cnt - req->pnt;
  rc = SSL_write(ssl_h, (char*)req->buf + req->pnt, to_snd);

  if (rc == -1)
    return -1;
  if (rc == 0)
    return -2;

  req->pnt = (req->pnt + rc) % req->cnt;

  return rc;
}

inline int pb_socket_recv_reply(ping_buffer* pb, int sd)
{
  int rc, old_pnt;
  int to_recv;
  _buffer* rep;

  if (pb == NULL || (rep = pb->reply) == NULL)
    return -1;
  if (rep->cnt == rep->size) /* read required */
    return -2;


  to_recv = (rep->available >= rep->pnt) ? rep->size - rep->available : rep->pnt - rep->available;
  old_pnt = rep->pnt;
  if ((rc = read(sd, (char*)rep->buf + rep->available, to_recv)) < 0)
    {
      rep->pnt = old_pnt; //see man 2 read
      return -1;
    }

  rep->available = (rep->available + rc) % rep->size;
  rep->cnt = rep->cnt + rc ;

  return rc;
}

int pb_ssl_recv_reply(ping_buffer* pb, SSL* ssl_h)
{
  int rc, old_pnt;
  int to_recv;
  _buffer* rep;

  if (pb == NULL || (rep = pb->reply) == NULL)
    return -1;
  if (rep->cnt == rep->size) /* read required */
    return -2;

  to_recv = (rep->available >= rep->pnt) ? rep->size - rep->available : rep->pnt - rep->available;

  old_pnt = rep->pnt;
  if ((rc = SSL_read(ssl_h, (char*)rep->buf + rep->available, to_recv)) < 0)
    {
      rep->pnt = old_pnt; //see man 2 read
      return -1;
    }
  rep->available = (rep->available + rc) % rep->size;
  rep->cnt = rep->cnt + rc ;

  return rc;
}

int pb_get_cnt_reply(ping_buffer* pb)
{
  if (pb == NULL || pb->reply == NULL)
    return -1;

  return pb->reply->cnt;
}

int pb_get_cnt_request(ping_buffer* pb)
{
  if (pb == NULL || pb->request == NULL)
    return -1;

  return pb->request->cnt;
}
