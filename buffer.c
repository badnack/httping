#include "buffer.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

ping_buffer* pb_create(int size)
{
  ping_buffer* pb;
  
  if ((pb = (ping_buffer*) malloc(sizeof (ping_buffer) + (sizeof (char) * size))) == NULL)
    return NULL;
  memset(pb, 0, sizeof (ping_buffer) + (sizeof (char) * size));
  pb->size = size;
  pb->to_read = 0;
  pb->to_write = 0;
  pb->r_pnt = 0;
  pb->w_pnt = 0;

  return pb;
}

int pb_sprintf(ping_buffer *pb, char* fmt, ...){
  char* formatted_string;
  va_list argptr;
  int cnt;

  if (pb == NULL)
    return 0;
  if ((cnt = pb->size - pb->to_write + 1) <= 0)
    return 0;
  if ((formatted_string = (char*)calloc(cnt, sizeof(char))) == NULL)
    return 0;

  va_start(argptr,fmt);
  vsnprintf(formatted_string, cnt - 1, fmt, argptr);
  va_end(argptr);
  pb->to_write = sprintf(pb->buf, "%s", formatted_string); 
  
  free(formatted_string);
  return pb->to_write;
}

int pb_strcat(ping_buffer* pb, char* fmt, ...){
  char* formatted_string;
  va_list argptr;
  int cnt, tot;

  if (pb == NULL)
    return 0;
  if ((cnt = pb->size - pb->to_write + 1) <= 0)
    return 0;
  if ((formatted_string = (char*)calloc(cnt, sizeof(char))) == NULL)
    return 0;

  va_start(argptr,fmt);
  vsnprintf(formatted_string, cnt - 1, fmt, argptr);
  va_end(argptr);
  tot = sprintf(&pb->buf[pb->to_write], "%s", formatted_string); 
  pb->to_write += tot;  
  free(formatted_string);
  return tot;

}
