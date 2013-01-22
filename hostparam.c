#include "hostparam.h"

void hp_set_start_values(host_param* hp)
{
  if (hp == NULL)
    return;

  hp->min = 999999999999999.0;
  hp->Bps_min = 1 << 30;
  hp->avg_httping_time = -1.0;
  hp->ssl_h = NULL;
  hp->header = NULL;
  hp->header_len = 0;

}

int hp_max_fd(host_param *hp, int n)
{
  int i, max;

  if (n <= 0)
    return -1;

  max = hp[0].ph.fd;
  for(i = 0; i < n; i++)
    {
      if (max < hp[i].ph.fd)
        max = hp[i].ph.fd;
    }
  return max;
}
