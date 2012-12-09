/* The GPL applies to this program.
  In addition, as a special exception, the copyright holders give
  permission to link the code of portions of this program with the
  OpenSSL library under certain conditions as described in each
  individual source file, and distribute linked combinations
  including the two.
  You must obey the GNU General Public License in all respects
  for all of the code used other than OpenSSL.  If you modify
  file(s) with this exception, you may extend this exception to your
  version of the file(s), but you are not obligated to do so.  If you
  do not wish to do so, delete this exception statement from your
  version.  If you delete this exception statement from all source
  files in the program, then also delete it here.
*/

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gen.h"
#include "res.h"
#include "error.h"

extern char last_error[];

int resolve_host(char *host, struct addrinfo **ai, char use_ipv6, int portnr)
{
	char servname[10];
	struct addrinfo myaddr;
	memset(&myaddr, 0, sizeof(myaddr));
	/* myaddr.ai_flags = AI_PASSIVE; */
	myaddr.ai_socktype = SOCK_STREAM;
	myaddr.ai_protocol = IPPROTO_TCP;
	myaddr.ai_family = use_ipv6 ? AF_INET6 : AF_INET;
	snprintf(servname, sizeof(servname), "%d", portnr);

	if (getaddrinfo(host, servname, &myaddr, ai))
		error_exit("Error resolving '%s'", host);

	return 0;
}

struct addrinfo * select_resolved_host(struct addrinfo *ai, char use_ipv6)
{
	struct addrinfo *p = ai;
	while(p)
	{
		if (p -> ai_family == AF_INET6 && use_ipv6)
			return p;

		if (p -> ai_family == AF_INET)
			return ai;
	}

	return NULL;
}

void get_addr(struct addrinfo *ai_use, struct sockaddr_in6 *addr)
{
	memcpy(addr, ai_use->ai_addr, ai_use->ai_addrlen);
}
