#include "handler.h"
#include <stdio.h>
#include <stdlib.h>

void ph_init(ping_handler *ph, int size, int(*io_read)(int), int (*io_write)(int))
{
  if(ph == NULL)
    return;

  ph->state = 0; //wait connection
  ph->fd = -1;
  ph->f_io[0] = io_read;
  ph->f_io[1] = io_write;
  ph->pnt = 0;
  ph->size = size;
  ph->buf = (char*) calloc(sizeof(char), size);
}

void ph_free(ping_handler *ph)
{
  if(ph == NULL )
    return;
  if(ph->buf != NULL && ph->size > 0)
    free(ph->buf);
  ph->size = ph->pnt = 0;
  ph->f_io[0] = ph->f_io[1] = NULL;
  ph->fd = -1;
  ph->state = 0;
}
