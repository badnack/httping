#include "handler.h"
#include <stdio.h>
#include <stdlib.h>

void ph_init(ping_handler *ph)
{
  if(ph == NULL)
    return;

  ph->state = 0; //wait connection
  ph->fd = -1;
}
