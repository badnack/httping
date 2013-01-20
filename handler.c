#include "handler.h"
#include "buffer.h"
#include <stdio.h>
#include <stdlib.h>

int ph_init(ping_handler *ph, int s_size, int r_size)
{
  if(ph == NULL)
    return -1;
  ph->state = 0; //wait connection
  ph->fd = -1;

  if((ph->data = (ping_buffer*) pb_create(s_size)) == NULL)
    return -1;
  if((ph->request = (ping_buffer*) pb_create(r_size)) == NULL)
    return -1;

  return 0;
}
