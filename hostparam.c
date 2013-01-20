#include "hostparam.h"

int max_fd(host_param *hp, int n)
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
