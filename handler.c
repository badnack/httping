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
  
  ph->data = ph->request = NULL;
  if((s_size > 0) && (ph->data = (ping_buffer*) pb_create(s_size)) == NULL)
    return -1;
  if((r_size > 0) && (ph->request = (ping_buffer*) pb_create(r_size)) == NULL)
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
