#include "buffer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

ping_buffer* create_buffer(int size)
{
  ping_buffer* pb;
  if ((pb = (ping_buffer*) malloc(sizeof (ping_buffer) + (sizeof (char) * size))) == NULL)
    return NULL;

  pb->size = size;
  pb->to_read = 0;
  pb->to_write = 0;
  pb->r_pnt = 0;
  pb->w_pnt = 0;

  return pb;
}

void spprintf(ping_buffer *pb, char* fmt, ...){
  char formatted_string[pb->size - pb->to_write + 1];
  va_list argptr;

  if (pb == NULL)
    return;

  va_start(argptr,fmt);
  vsnprintf(formatted_string, pb->size - pb->to_write, fmt, argptr);
  va_end(argptr);
  pb->to_write = sprintf(pb->buf, "%s", formatted_string); 
}

void spcat(ping_buffer* pb, char* fmt, ...){
  char formatted_string[pb->size - pb->to_write + 1];
  va_list argptr;

  if (pb == NULL)
    return;

  va_start(argptr,fmt);
  vsnprintf(formatted_string, pb->size - pb->to_write, fmt, argptr);
  va_end(argptr);
  pb->to_write += sprintf(&pb->buf[pb->to_write], "%s", formatted_string); 
}
