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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#ifndef NO_SSL
#include <openssl/ssl.h>
#include "mssl.h"
#endif
#include <arpa/inet.h>

#include "gen.h"
#include "http.h"
#include "io.h"
#include "str.h"
#include "mem.h"
#include "tcp.h"
#include "res.h"
#include "utils.h"
#include "error.h"
#include "hostparam.h"

#define BUF_SIZE 4096

typedef struct host_param host_param;

static volatile int stop = 0;

int quiet = 0;
char machine_readable = 0;
char nagios_mode = 0;
char last_error[ERROR_BUFFER_SIZE];

void version(void)
{
  fprintf(stderr, "HTTPing v" VERSION ", (C) 2003-2012 folkert@vanheusden.com\n");
#ifndef NO_SSL
  fprintf(stderr, "SSL support included\n");
#endif
}

void usage(void)
{
  fprintf(stderr, "-p portnr      portnumber (e.g. 80)\n");
  fprintf(stderr, "-x host:port   hostname+portnumber of proxyserver\n");
  fprintf(stderr, "-c count       how many times to connect\n");
  fprintf(stderr, "-i interval    delay between each connect, can be only smaller than 1 if user is root\n");
  fprintf(stderr, "-t timeout     timeout (default: 30s)\n");
  fprintf(stderr, "-Z             ask any proxies on the way not to cache the requests\n");
  fprintf(stderr, "-Q             use a persistent connection. adds a 'C' to the output if httping had to reconnect\n");
  fprintf(stderr, "-6             use IPv6\n");
  fprintf(stderr, "-s             show statuscodes\n");
  fprintf(stderr, "-S             split time in connect-time and processing time\n");
  fprintf(stderr, "-G             do a GET request instead of HEAD (read the\n");
  fprintf(stderr, "               contents of the page as well)\n");
  fprintf(stderr, "-b             show transfer speed in KB/s (use with -G)\n");
  fprintf(stderr, "-B             like -b but use compression if available\n");
  fprintf(stderr, "-L x           limit the amount of data transferred (for -b)\n");
  fprintf(stderr, "               to 'x' (in bytes)\n");
  fprintf(stderr, "-X             show the number of KB transferred (for -b)\n");
#ifndef NO_SSL
  fprintf(stderr, "-l             connect using SSL\n");
  fprintf(stderr, "-z             show fingerprint (SSL)\n");
#endif
  fprintf(stderr, "-f             flood connect (no delays)\n");
  fprintf(stderr, "-a             audible ping\n");
  fprintf(stderr, "-m             give machine parseable output (see\n");
  fprintf(stderr, "               also -o and -e)\n");
  fprintf(stderr, "-o rc,rc,...   what http results codes indicate 'ok'\n");
  fprintf(stderr, "               coma seperated WITHOUT spaces inbetween\n");
  fprintf(stderr, "               default is 200, use with -e\n");
  fprintf(stderr, "-e str         string to display when http result code\n");
  fprintf(stderr, "               doesn't match\n");
  fprintf(stderr, "-I str         use 'str' for the UserAgent header\n");
  fprintf(stderr, "-R str         use 'str' for the Referer header\n");
  fprintf(stderr, "-r             resolve hostname only once (usefull when\n");
  fprintf(stderr, "               pinging roundrobin DNS: also takes the first\n");
  fprintf(stderr, "               DNS lookup out of the loop so that the first\n");
  fprintf(stderr, "               measurement is also correct)\n");
  fprintf(stderr, "-n warn,crit   Nagios-mode: return 1 when avg. response time\n");
  fprintf(stderr, "               >= warn, 2 if >= crit, otherwhise return 0\n");
  fprintf(stderr, "-N x           Nagios mode 2: return 0 when all fine, 'x'\n");
  fprintf(stderr, "               when anything failes\n");
  fprintf(stderr, "-y ip[:port]   bind to ip-address (and thus interface) [/port]\n");
  fprintf(stderr, "-q             quiet, only returncode\n");
  fprintf(stderr, "-A             Activate Basic authentication\n");
  fprintf(stderr, "-U Username    needed for authentication\n");
  fprintf(stderr, "-P Password    needed for authentication\n");
  fprintf(stderr, "-C cookie=value Add a cookie to the request\n");
  fprintf(stderr, "-V             show the version\n\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "--port			-p\n");
  fprintf(stderr, "--host-port		-x\n");
  fprintf(stderr, "--count		-c\n");
  fprintf(stderr, "--interval		-i\n");
  fprintf(stderr, "--timeout		-t\n");
  fprintf(stderr, "--ipv6		-	6\n");
  fprintf(stderr, "--show-statusodes	-s\n");
  fprintf(stderr, "--split-time		-S\n");
  fprintf(stderr, "--get-request		-G\n");
  fprintf(stderr, "--show-transfer-speed	-b\n");
  fprintf(stderr, "--show-xfer-speed-compressed		-B\n");
  fprintf(stderr, "--data-limit		-L\n");
  fprintf(stderr, "--show-kb		-X\n");
#ifndef NO_SSL
  fprintf(stderr, "--use-ssl		-l\n");
  fprintf(stderr, "--show-fingerprint	-z\n");
#endif
  fprintf(stderr, "--flood		-f\n");
  fprintf(stderr, "--audible-ping		-a\n");
  fprintf(stderr, "--parseable-output	-m\n");
  fprintf(stderr, "--ok-result-codes	-o\n");
  fprintf(stderr, "--result-string	-e\n");
  fprintf(stderr, "--user-agent		-I\n");
  fprintf(stderr, "--referer		-S\n");
  fprintf(stderr, "--resolve-once		-r\n");
  fprintf(stderr, "--nagios-mode-1	-n\n");
  fprintf(stderr, "--nagios-mode-2	-n\n");
  fprintf(stderr, "--bind-to		-y\n");
  fprintf(stderr, "--quiet		-q\n");
  fprintf(stderr, "--basic-auth		-A\n");
  fprintf(stderr, "--username		-U\n");
  fprintf(stderr, "--password		-P\n");
  fprintf(stderr, "--cookie		-C\n");
  fprintf(stderr, "--persistent-connections	-Q\n");
  fprintf(stderr, "--no-cache		-Z\n");
  fprintf(stderr, "--tcp-fast-open        -F\n");
  fprintf(stderr, "--version		-V\n");
  fprintf(stderr, "--help			-h\n");
}

void emit_error()
{
  if (!quiet && !machine_readable && !nagios_mode)
    {
      printf("%s", last_error);
    }

  if (!nagios_mode)
    last_error[0] = 0x00;

  fflush(NULL);
}

void handler(int sig)
{
  fprintf(stderr, "Got signal %d\n", sig);
  stop = 1;
}

/* Base64 encoding start */
const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void encode_tryptique(char source[3], char result[4])
/* Encode 3 char in B64, result give 4 Char */
{
  int tryptique, i;
  tryptique = source[0];
  tryptique *= 256;
  tryptique += source[1];
  tryptique *= 256;
  tryptique += source[2];
  for (i=0; i<4; i++)
    {
      result[3-i] = alphabet[tryptique%64];
      tryptique /= 64;
    }
}


int enc_b64(char *source, size_t source_lenght, char *target)
{
  /* Divide string /3 and encode trio */
  while (source_lenght >= 3) {
    encode_tryptique(source, target);
    source_lenght -= 3;
    source += 3;
    target += 4;
  }
  /* Add padding to the rest */
  if (source_lenght > 0) {
    char pad[3];
    memset(pad, 0, sizeof(pad));
    memcpy(pad, source, source_lenght);
    encode_tryptique(pad, target);
    target[3] = '=';
    if (source_lenght == 1) target[2] = '=';
    target += 4;
  }
  target[0] = 0;
  return 1;
}
/* Base64 encoding END */

int main(int argc, char *argv[])
{
  int n_hosts = 0, wait_read = 0, n_partial_write = 0, n_partial_read = 0;
  int goto_loop;
  char *proxy = NULL, *proxyhost = NULL;
  int proxyport = 8080;
  int portnr = 80;
  char *get = NULL;
  int c = 0;
  int count = -1, curncount = 0;
  double wait = 1.0;
  int audible = 0;
  int ok = 0;
  int timeout=30;
  char show_statuscodes = 0;
  char use_ssl = 0;
  char *ok_str = "200";
  char *err_str = "-1";
  char *useragent = NULL;
  char *referer = NULL;
  char *host = NULL;
  char *pwd = NULL;
  char *usr = NULL;
  char *cookie = NULL;
  int port = 0;
  char resolve_once = 0;
  char auth_mode = 0;
  int  req_sent = 0;
  double nagios_warn=0.0, nagios_crit=0.0;
  int nagios_exit_code = 2;
  int get_instead_of_head = 0;
  char *buffer = NULL;
  int page_size = sysconf(_SC_PAGESIZE);
  char show_Bps = 0, ask_compression = 0;
  int Bps_limit = -1;
  char show_bytes_xfer = 0, show_fp = 0;
  struct sockaddr_in *bind_to = NULL;
  struct sockaddr_in bind_to_4;
  struct sockaddr_in6 bind_to_6;
  host_param *hp;
  char bind_to_valid = 0;
  char split = 0, use_ipv6 = 0;
  char persistent_connections = 0;
  char no_cache = 0;
  int tfo = 0;
  int index;
  fd_set rd, wr;
  int type_err;

  static struct option long_options[] =
    {
      {"port",	1, NULL, 'p' },
      {"host-port",	1, NULL, 'x' },
      {"count",	1, NULL, 'c' },
      {"persistent-connections",	0, NULL, 'Q' },
      {"interval",	1, NULL, 'i' },
      {"timeout",	1, NULL, 't' },
      {"ipv6",	0, NULL, '6' },
      {"show-statusodes",	0, NULL, 's' },
      {"split-time",	0, NULL, 'S' },
      {"get-request",	0, NULL, 'G' },
      {"show-transfer-speed",	0, NULL, 'b' },
      {"show-xfer-speed-compressed",	0, NULL, 'B' },
      {"data-limit",	1, NULL, 'L' },
      {"show-kb",	0, NULL, 'X' },
      {"no-cache",	0, NULL, 'Z' },
#ifndef NO_SSL
      {"use-ssl",	0, NULL, 'l' },
      {"show-fingerprint",	0, NULL, 'z' },
#endif
      {"flood",	0, NULL, 'f' },
      {"audible-ping",	0, NULL, 'a' },
      {"parseable-output",	0, NULL, 'm' },
      {"ok-result-codes",	1, NULL, 'o' },
      {"result-string",	1, NULL, 'e' },
      {"user-agent",	1, NULL, 'I' },
      {"referer",	1, NULL, 'S' },
      {"resolve-once",0, NULL, 'r' },
      {"nagios-mode-1",	1, NULL, 'n' },
      {"nagios-mode-2",	1, NULL, 'n' },
      {"bind-to",	1, NULL, 'y' },
      {"quiet",	0, NULL, 'q' },
      {"basic-auth",	0, NULL, 'A' },
      {"username",	1, NULL, 'U' },
      {"password",	1, NULL, 'P' },
      {"cookie",	1, NULL, 'C' },
      {"version",	0, NULL, 'V' },
      {"help",	0, NULL, 'h' },
      {NULL,		0, NULL, 0   }
    };

  signal(SIGPIPE, SIG_IGN);

  if (page_size == -1)
    page_size = 4096;

  buffer = (char *)mymalloc(page_size, "receive buffer");

  while((c = getopt_long(argc, argv, "ZQ6Sy:XL:bBp:c:i:Gx:t:o:e:falqsmV?I:R:rn:N:z:AP:U:C:F", long_options, NULL)) != -1)
    {
      switch(c)
        {
        case 'Z':
          no_cache = 1;
          break;

        case '6':
          use_ipv6 = 1;
          break;

        case 'S':
          split = 1;
          break;

        case 'Q':
          persistent_connections = 1;
          break;

        case 'y':
          {
            char *dummy = strchr(optarg, ':');

            bind_to_valid = 1;

            if (dummy)
              {
                bind_to = (struct sockaddr_in *)&bind_to_6;
                memset(&bind_to_6, 0x00, sizeof(bind_to_6));
                bind_to_6.sin6_family = AF_INET6;

                if (inet_pton(AF_INET6, optarg, &(bind_to_6.sin6_addr)) != 1)
                  {
                    error_exit("cannot convert ip address '%s' (for -y)\n", optarg);
                  }
              }
            else
              {
                bind_to = (struct sockaddr_in *)&bind_to_4;
                memset(&bind_to_4, 0x00, sizeof(bind_to_4));
                bind_to_4.sin_family = AF_INET;

                if (inet_pton(AF_INET, optarg, &(bind_to_4.sin_addr)) != 1)
                  {
                    error_exit("cannot convert ip address '%s' (for -y)\n", optarg);
                  }
              }
          }
          break;

        case 'z':
          show_fp = 1;
          break;

        case 'X':
          show_bytes_xfer = 1;
          break;

        case 'L':
          Bps_limit = atoi(optarg);
          break;

        case 'B':
          show_Bps = 1;
          ask_compression = 1;
          break;

        case 'b':
          show_Bps = 1;
          break;

        case 'e':
          err_str = optarg;
          break;

        case 'o':
          ok_str = optarg;
          break;

        case 'x':
          proxy = optarg;
          break;

        case 'r':
          resolve_once = 1;
          break;

        case 'p':
          portnr = atoi(optarg);
          break;

        case 'c':
          count = atoi(optarg);
          break;

        case 'i':
          wait = atof(optarg);
          if (wait < 1.0 && getuid() != 0)
            {
              fprintf(stderr, "Only root can use intervals smaller than 1\n");
              wait = 1.0;
            }
          break;

        case 't':
          timeout = atoi(optarg);
          break;

        case 'I':
          useragent = optarg;
          break;

        case 'R':
          referer = optarg;
          break;

        case 'a':
          audible = 1;
          break;

        case 'f':
          wait = 0;
          break;

        case 'G':
          get_instead_of_head = 1;
          break;

#ifndef NO_SSL
        case 'l':
          use_ssl = 1;
          break;
#endif

        case 'm':
          machine_readable = 1;
          break;

        case 'q':
          quiet = 1;
          break;

        case 's':
          show_statuscodes = 1;
          break;

        case 'V':
          version();
          return 0;

        case 'n':
          {
            char *dummy = strchr(optarg, ',');
            if (nagios_mode) error_exit("-n and -N are mutual exclusive\n");
            nagios_mode = 1;
            if (!dummy)
              error_exit("-n: missing parameter\n");
            nagios_warn = atof(optarg);
            nagios_crit = atof(dummy + 1);
          } break;
        case 'N':
          if (nagios_mode) error_exit("-n and -N are mutual exclusive\n");
          nagios_mode = 2;
          nagios_exit_code = atoi(optarg);
          break;
        case 'A':
          auth_mode = 1;
          break;
        case 'P':
          pwd = optarg;
          break;
        case 'U':
          usr = optarg;
          break;
        case 'C':
          cookie = optarg;
          break;
        case 'F':
#ifdef TCP_TFO
          tfo = 1;
#else
          printf("Warning: No TCP TFO Supported.. Disabling..\n");
#endif
          break;
        case '?':
        default:
          version();
          usage();
          return 1;
        }
    }

#ifndef NO_SSL
  if (use_ssl && portnr == 80)
    portnr = 443;
#endif

  /* Multihost hosts */
  n_hosts = argc - optind;
  if (!n_hosts)
    {
      usage();
      error_exit("No hostname/getrequest given\n");
    }

  hp = (host_param*) calloc(sizeof(host_param), n_hosts);

  while (optind < argc)
    {
      int i = n_hosts - (argc - optind);

      char *slash, *colon;
      char *getcopy = argv[optind];

      if (strncasecmp(getcopy, "http://", 7) == 0)
        {
          getcopy += 7;
        }
      else if (strncasecmp(getcopy, "https://", 8) == 0)
        {
          getcopy += 8;
          hp[i].use_ssl = 1;
        }

      slash = strchr(getcopy, '/');
      if (slash)
        *slash = 0x00;

      if (!use_ipv6)
        {
          colon = strchr(getcopy, ':');
          if (colon)
            {
              *colon = 0x00;
              hp[i].portnr = atoi(colon + 1); /* per host port number */
            }
          else
            {
              hp[i].portnr = portnr; /* global port number */
            }
        }
      hp[i].name = strdup(getcopy);
#ifndef NO_SSL
      if (hp[i].use_ssl && hp[i].portnr == 80)
        hp[i].portnr = 443;
#endif
      optind++;
    }

  last_error[0] = 0x00;

  if (!get_instead_of_head && show_Bps)
    error_exit("-b/-B can only be used when also using -G\n");

  if(tfo && use_ssl)            /* FIXME: check hp[index].use_ssl also */
    error_exit("TCP Fast open and SSL not supported together\n");

  /* init variables */
  FD_ZERO(&rd);
  FD_ZERO(&wr);

  for(index = 0; index < n_hosts; index++)
    {
      hp[index].min = 999999999999999.0; //FIXE change in init funcion
      hp[index].Bps_min = 1 << 30;
      hp[index].avg_httping_time = -1.0;
      hp[index].ssl_h = NULL;
      hp[index].partial_write = 0;
      hp[index].partial_read = 0;
      hp[index].header = NULL;
      hp[index].header_len = 0;

#ifndef NO_SSL
      if (hp[index].use_ssl || use_ssl)
        {
          get = mymalloc(8 /* http:// */ + strlen(hp[index].name) + 1 /* colon */ + 5 /* portnr */ + 1 /* / */ + 1 /* 0x00 */, "get");
          sprintf(get, "https://%s:%d/", hp[index].name, hp[index].portnr);
        }
      else
        {
#endif
          get = mymalloc(7 /* http:// */ + strlen(hp[index].name) + 1 /* colon */ + 5 /* portnr */ + 1 /* / */ + 1 /* 0x00 */, "get");
          sprintf(get, "http://%s:%d/", hp[index].name, hp[index].portnr);
#ifndef NO_SSL
        }
#endif

      if (proxy)
        {
          char *dummy = strchr(proxy, ':');
          proxyhost = proxy;
          if (dummy)
            {
              *dummy=0x00;
              proxyport = atoi(dummy + 1);
            }

          if (!quiet && !nagios_mode)
            fprintf(stderr, "Using proxyserver: %s:%d\n", proxyhost, proxyport);
        }

#ifndef NO_SSL
      if (hp[index].use_ssl || use_ssl)
        {
          hp[index].client_ctx = initialize_ctx();
          if (!hp[index].client_ctx)
            {
              snprintf(last_error, ERROR_BUFFER_SIZE, "problem creating SSL context\n");
              hp[index].fatal = 1;
              continue;
            }
        }
#endif

      if (ph_init(&hp[index].ph, BUF_SIZE, strlen(get) + 8192) < 0)
        error_exit("\nSystem error\n");
      if (proxyhost)
        pb_write_request(&hp[index].ph.pb, 1, "%s %s HTTP/1.%c\r\n", get_instead_of_head?"GET":"HEAD", get, persistent_connections?'1':'0');
      else
        {
          char *dummy = get, *slash;
          if (strncasecmp(dummy, "http://", 7) == 0)
            dummy += 7;
          else if (strncasecmp(dummy, "https://", 7) == 0)
            dummy += 8;

          slash = strchr(dummy, '/');
          if (slash)
            pb_write_request(&hp[index].ph.pb, 1, "%s %s HTTP/1.%c\r\n", get_instead_of_head?"GET":"HEAD", slash, persistent_connections?'1':'0');
          else
            pb_write_request(&hp[index].ph.pb, 1, "%s / HTTP/1.%c\r\n", get_instead_of_head?"GET":"HEAD", persistent_connections?'1':'0');
        }
      if (useragent)
        pb_write_request(&hp[index].ph.pb, 1, "User-Agent: %s\r\n", useragent);
      else
        pb_write_request(&hp[index].ph.pb, 1, "User-Agent: HTTPing v" VERSION "\r\n");
      pb_write_request(&hp[index].ph.pb, 1, "Host: %s\r\n", hp[index].name);
      if (referer)
        pb_write_request(&hp[index].ph.pb, 1, "Referer: %s\r\n", referer);
      if (ask_compression)
        pb_write_request(&hp[index].ph.pb, 1, "Accept-Encoding: gzip,deflate\r\n");

      if (no_cache)
        {
          pb_write_request(&hp[index].ph.pb, 1, "Pragma: no-cache\r\n");
          pb_write_request(&hp[index].ph.pb, 1, "Cache-Control: no-cache\r\n");
        }

      /* Basic Authentification */
      if (auth_mode) {
        char auth_string[255];
        char b64_auth_string[255];
        if (usr == NULL)
          error_exit("Basic Authnetication (-A) can only be used with a username and/or password (-U -P) ");
        sprintf(auth_string,"%s:%s",usr,pwd);
        enc_b64(auth_string, strlen(auth_string), b64_auth_string);
        pb_write_request(&hp[index].ph.pb, 1, "Authorization: Basic %s\r\n", b64_auth_string);
      }

      /* Cookie Insertion */
      if (cookie) {
        pb_write_request(&hp[index].ph.pb, 1, "Cookie: %s;\r\n", cookie);
      }

      if (persistent_connections)
        pb_write_request(&hp[index].ph.pb, 1, "Connection: keep-alive\r\n");

      pb_write_request(&hp[index].ph.pb, 1, "\r\n");

      if (!quiet && !machine_readable && !nagios_mode )
        printf("PING %s:%d (%s):\n", hp[index].name, hp[index].portnr, get);
      if (get != NULL)
        {
          free(get);
          get = NULL;
        }
    } /* end for(index) */

  signal(SIGINT, handler);
  signal(SIGTERM, handler);

  timeout *= 1000;	/* change to ms */

  /* struct sockaddr_in6 addr; */
  struct addrinfo *ai = NULL, *ai_use;
  double started_at = get_ts();
  struct timeval to;

  to.tv_sec = wait + 5;
  to.tv_usec = 0;

  while((curncount < count || count == -1) && stop == 0)
    {
      double ms;
      double dafter_connect = 0.0;
      char *reply;
      char is_compressed = 0;
      char *fp = NULL;
      int rc, ret;
      char *scdummy = NULL;
      int len = 0, overflow = 0;

      goto_loop = 0;
      for(index = 0; index < n_hosts; index++)
        {
          if (hp[index].ph.state == 0 && !hp[index].fatal)
            {
              hp[index].sc = NULL;
              host = proxyhost ? proxyhost : hp[index].name;
              port = proxyhost ? proxyport : hp[index].portnr;
            persistent_loop:
              if (hp[index].ph.fd == -1 && (!resolve_once || (resolve_once == 1 && hp[index].have_resolved == 0)))
                {
                  memset(&hp[index].addr, 0x00, sizeof(hp[index].addr));

                  if (ai)
                    {
                      freeaddrinfo(ai);
                      ai = NULL;
                    }

                  if (resolve_host(host, &ai, use_ipv6, port) == -1)
                    {
                      hp[index].err++;
                      emit_error();
                      hp[index].have_resolved = 1;
                      continue;
                    }
                  ai_use = select_resolved_host(ai, use_ipv6);
                  get_addr(ai_use, &hp[index].addr);
                }

              req_sent = 0;

              if ((persistent_connections && hp[index].ph.fd < 0) || (!persistent_connections))
                {
                  hp[index].dstart = get_ts();
                 hp[index].ph.fd = connect_to((struct sockaddr *)(bind_to_valid?bind_to:NULL), ai, timeout, tfo, ((_buffer*)(hp[index].ph.pb.request))->buf, ((_buffer*)(hp[index].ph.pb.request))->available, &req_sent); //FIXME
                }
              if (hp[index].ph.fd == -3)
                  continue;
              if (hp[index].ph.fd < 0)
                {
                  emit_error();
                  hp[index].ph.fd = -1;
                  continue;
                }

              if (hp[index].ph.fd >= 0)
                {
                  /* set socket to low latency */
                  if (set_tcp_low_latency(hp[index].ph.fd) == -1)
                    {
                      close(hp[index].ph.fd);
                      hp[index].ph.fd = -1;
                      continue;
                    }

                  /* set fd blocking */
                  if (set_fd_blocking(hp[index].ph.fd) == -1)
                    {
                      close(hp[index].ph.fd);
                      hp[index].ph.fd = -1;
                      continue;
                    }

#ifndef NO_SSL
                  if ((hp[index].use_ssl || use_ssl) && hp[index].ssl_h == NULL)
                    {
                      BIO *s_bio = NULL;
                      rc = connect_ssl(hp[index].ph.fd, hp[index].client_ctx, &hp[index].ssl_h, &s_bio, timeout);
                      if (rc != 0)
                        {
                          close(hp[index].ph.fd);
                          hp[index].ph.fd = rc;

                          if (persistent_connections)
                            {
                              if (++hp[index].persistent_tries < 2)
                                {
                                  close(hp[index].ph.fd);
                                  hp[index].ph.fd = -1;
                                  hp[index].persistent_did_reconnect = 1;
                                  goto persistent_loop;
                                }
                            }
                        }
                    }
#endif
                  hp[index].ph.state = (req_sent) ? 2 : 1;
                }

              if (split)
                dafter_connect = get_ts();


              if (hp[index].ph.fd < 0)
                {
                  if (hp[index].ph.fd == -2)
                    snprintf(last_error, ERROR_BUFFER_SIZE, "timeout connecting to host\n");
                  emit_error();
                  hp[index].ph.state = 0;
                  hp[index].ph.fd = -1;
                  continue;
                }
            }//end state == 0

          //states
          if (hp[index].ph.state == 0)//request connection again
            {
              FD_CLR(hp[index].ph.fd, &rd);
              FD_CLR(hp[index].ph.fd, &wr);
            }
          else if (hp[index].ph.state == 1)//ready to write request
            FD_SET(hp[index].ph.fd, &wr);
          else if (hp[index].ph.state == 2)//ready to read Header
            FD_SET(hp[index].ph.fd, &rd);
          else if (hp[index].ph.state == 3)//ready to read Body
            FD_SET(hp[index].ph.fd, &rd);

          if (goto_loop)
            {
              goto_loop = 0;
              break;
            }
        }//end for
      if ((ret = select(max_fd(hp, n_hosts) + 1 , &rd, &wr, NULL, &to)) <= 0)
        {
          if (ret == 0)
            error_exit("\nNo more hosts available\n");
          error_exit("\nSystem error (select)\n"); //BUG: ctrl+c sometimes bring here!
        }
      for (index = 0; index < n_hosts; index++)
        {
          if (FD_ISSET(hp[index].ph.fd, &wr) && hp[index].ph.state == 1)
            {
              if (get_ts() < hp[index].wait)
                continue;
#ifndef NO_SSL
              if (hp[index].use_ssl || use_ssl)
                rc = ph_send_ssl(hp[index].ssl_h, &hp[index].ph);
              else
#endif
                {
                  if (!req_sent)
                    {
                      hp[index].dstart = get_ts();
                      rc = ph_send(&hp[index].ph);
                    }
                  else
                    rc = 1;
                }

              if (rc < 0) //errors
                {
                  if (persistent_connections)
                    {
                      if (++hp[index].persistent_tries < 2)
                        {
                          close(hp[index].ph.fd);
                          hp[index].persistent_did_reconnect = 1;
                          hp[index].ph.fd = -1;
                          hp[index].ph.state = 0;
                          goto_loop = 1;
                          goto persistent_loop;
                        }
                    }
                  emit_error();
                  close(hp[index].ph.fd);
                  hp[index].ph.fd = -1;
                  hp[index].ph.state = 0;
                  hp[index].err++;
                  continue;
                }
              else if (rc == 0) //rc == 0: write not yet completed
                {
                  if (hp[index].partial_write == 0)
                    {
                      n_partial_write++;
                      hp[index].partial_write = 1;
                    }
                  continue;
                }

              //write completed
              wait_read++;
              hp[index].ph.state = 2;

              if (hp[index].partial_write == 1)
                {
                  if (n_partial_write > 0)
                    n_partial_write--;
                  hp[index].partial_write = 0;
                }
            }

          else if (FD_ISSET(hp[index].ph.fd, &rd) && (hp[index].ph.state == 2 || hp[index].ph.state == 3))
            {
              if (hp[index].ph.state == 2)
                {
#ifndef NO_SSL
                  if (hp[index].ssl_h)
                    rc = ph_recv_ssl_HTTP_header(&hp[index].ph, hp[index].ssl_h, &hp[index].header, &hp[index].header_len, &overflow); //FIXME
                  else
#endif
                    rc = ph_recv_HTTP_header(&hp[index].ph, &hp[index].header, &hp[index].header_len, &overflow); //FIXME

                  if (rc < 0)
                    {
                      if (persistent_connections)
                        {
                          if (++hp[index].persistent_tries < 2)
                            {
                              close(hp[index].ph.fd);
                              hp[index].ph.state = 0;
                              hp[index].ph.fd = -1;
                              hp[index].persistent_did_reconnect = 1;
                              goto_loop = 1;
                              goto persistent_loop;
                            }
                        }

                      if (rc == -1)
                        snprintf(last_error, ERROR_BUFFER_SIZE, "error receiving reply from host\n");

                      emit_error();

                      close(hp[index].ph.fd);
                      hp[index].ph.fd = -1;
                      hp[index].ph.state = 0;
                      hp[index].err++;
                      continue;
                    }

                  if (rc == 0) // partial read performed
                    {
                      if (hp[index].partial_read == 0)
                        {
                          n_partial_read++;
                          hp[index].partial_read = 1;
                        }
                      continue;
                    }

                  //complete read header
                  if (hp[index].partial_read == 1)
                    {
                      if (n_partial_read > 0)
                        n_partial_read--;
                      hp[index].partial_read = 0;
                    }
                  reply = hp[index].header;

                  if ((show_statuscodes || machine_readable) && reply != NULL)
                    {
                      /* statuscode is in first line behind
                       * 'HTTP/1.x'
                       */
                      char *dummy = strchr(reply, ' ');

                      if (dummy)
                        {
                          hp[index].sc = strdup(dummy + 1);

                          /* lines are normally terminated with a
                           * CR/LF
                           */
                          dummy = strchr(hp[index].sc, '\r');
                          if (dummy)
                            *dummy = 0x00;
                          dummy = strchr(hp[index].sc, '\n');
                          if (dummy)
                            *dummy = 0x00;
                        }
                    }

                  if (ask_compression && reply != NULL)
                    {
                      char *encoding = strstr(reply, "\nContent-Encoding:");
                      if (encoding)
                        {
                          char *dummy = strchr(encoding + 1, '\n');
                          if (dummy) *dummy = 0x00;
                          dummy = strchr(hp[index].sc, '\r');
                          if (dummy) *dummy = 0x00;

                          if (strstr(encoding, "gzip") == 0 || strstr(encoding, "deflate") == 0)
                            {
                              is_compressed = 1;
                            }
                        }
                    }

                  if (persistent_connections && show_bytes_xfer && reply != NULL)
                    {
                      char *length = strstr(reply, "\nContent-Length:");
                      if (!length)
                        {
                          snprintf(last_error, ERROR_BUFFER_SIZE, "'Content-Length'-header missing!\n");
                          emit_error();
                          close(hp[index].ph.fd);
                          hp[index].ph.fd = -1;
                          hp[index].ph.state = 0;
                          continue;
                        }
                      len = atoi(&length[17]);
                    }

                  if (reply != NULL)
                    {
                      hp[index].header_len = (strstr(reply, "\r\n\r\n") - reply) + 4;
                      free(hp[index].header);
                      hp[index].header = NULL;
                      reply = NULL;
                    }

                  hp[index].dl_start = get_ts(); //Just before the state 3
                  hp[index].bytes_transferred = 0;
                  if (persistent_connections)
                    {
                      if (hp[index].cur_limit == -1 || len < hp[index].cur_limit)
                        hp[index].cur_limit = len - overflow;
                    }
                  if (get_instead_of_head && show_Bps)
                    hp[index].ph.state = 3;
                  else
                    hp[index].ph.state = 4;

                } // end state == 2

              else if (hp[index].ph.state == 3)
                {
                  /* state 3 */
                  if (get_instead_of_head && show_Bps)
                    {
                      hp[index].cur_limit = Bps_limit;

                      rc = ph_recv_and_clean(&hp[index].ph);

                      if (rc < 0)
                        hp[index].fatal = 1;
                      else if (rc > 0)
                        {
                          hp[index].bytes_transferred += rc;
                          if (hp[index].cur_limit == -1 || (hp[index].cur_limit != -1 && hp[index].bytes_transferred < hp[index].cur_limit))
                            continue;
                        }

                      if(hp[index].fatal)
                        {
                          close(hp[index].ph.fd);
                          hp[index].ph.fd = -1;
                          hp[index].ph.state = 0;
                          continue;
                        }

                      hp[index].dl_end = get_ts();
                      hp[index].Bps = hp[index].bytes_transferred / max(hp[index].dl_end - hp[index].dl_start, 0.000001);
                      hp[index].Bps_min = min(hp[index].Bps_min, hp[index].Bps);
                      hp[index].Bps_max = max(hp[index].Bps_max, hp[index].Bps);
                      hp[index].Bps_avg += hp[index].Bps;
                    }
                  hp[index].ph.state = 4;
                } // end state 3
            }//end read state

          /* show result */
          if (hp[index].ph.state == 4)
            {
              hp[index].dend = get_ts();
              hp[index].ok++;
              hp[index].ph.state = 0;
              hp[index].curncount++;
              curncount++;
              wait_read--;
#ifndef NO_SSL
              if ((hp[index].use_ssl || use_ssl) && !persistent_connections)
                {
                  if (show_fp && hp[index].ssl_h != NULL)
                    {
                      fp = get_fingerprint(hp[index].ssl_h);
                    }

                  if (close_ssl_connection(hp[index].ssl_h, hp[index].ph.fd) == -1)
                    {
                      snprintf(last_error, ERROR_BUFFER_SIZE, "error shutting down ssl\n");
                      emit_error();
                    }

                  SSL_free(hp[index].ssl_h);
                  hp[index].ssl_h = NULL;
                }
#endif

              if (!persistent_connections)
                {
                  close(hp[index].ph.fd);
                  hp[index].ph.fd = -1;
                }

              ms = (hp[index].dend - hp[index].dstart) * 1000.0;
              hp[index].avg += ms;
              hp[index].min = hp[index].min > ms ? ms : hp[index].min;
              hp[index].max = hp[index].max < ms ? ms : hp[index].max;

              if (machine_readable)
                {
                  if (hp[index].sc)
                    {
                      char *dummy = strchr(hp[index].sc, ' ');

                      if (dummy) *dummy = 0x00;

                      if (strstr(ok_str, hp[index].sc))
                        {
                          printf("%f", ms);
                        }
                      else
                        {
                          printf("%s", err_str);
                        }

                      if (show_statuscodes)
                        printf(" %s", hp[index].sc);
                    }
                  else
                    {
                      printf("%s", err_str);
                    }
                  if(audible)
                    putchar('\a');
                  printf("\n");
                }
              else if (!quiet && !nagios_mode)
                {
                  char current_host[1024];
                  char *operation = !persistent_connections ? "connected to" : "pinged host";

                  if (getnameinfo((const struct sockaddr *)&hp[index].addr, sizeof(hp[index].addr), current_host, sizeof(current_host), NULL, 0, NI_NUMERICHOST) != 0)
                    snprintf(current_host, sizeof(current_host), "getnameinfo() failed: %d", errno);

                  if (persistent_connections && show_bytes_xfer)
                    printf("%s %s:%d (%s) (%d/%d bytes), seq=%d ", operation, current_host, hp[index].portnr, hp[index].name, hp[index].header_len, len, hp[index].curncount);
                  else
                    printf("%s %s:%d (%s) (%d bytes), seq=%d ", operation, current_host, hp[index].portnr, hp[index].name, hp[index].header_len, hp[index].curncount);

                  if (split)
                    printf("time=%.2f+%.2f=%.2f ms %s", (dafter_connect - hp[index].dstart) * 1000.0, (hp[index].dend - dafter_connect) * 1000.0, ms, hp[index].sc?hp[index].sc:"");
                  else
                    printf("time=%.2f ms %s", ms, hp[index].sc?hp[index].sc:"");

                  if (hp[index].persistent_did_reconnect)
                    {
                      printf(" C");
                      hp[index].persistent_did_reconnect = 0;
                    }

                  if (show_Bps)
                    {
                      printf(" %dKB/s", hp[index].Bps / 1024);
                      if (show_bytes_xfer)
                        printf(" %dKB", (int)(hp[index].bytes_transferred / 1024));
                      if (ask_compression)
                        {
                          printf(" (");
                          if (!is_compressed)
                            printf("not ");
                          printf("compressed)");
                        }
                    }

                  if ((hp[index].use_ssl || use_ssl) && show_fp && fp != NULL)
                    {
                      printf(" %s", fp);
                      free(fp);
                    }
                  if(audible)
                    putchar('\a');
                  printf("\n");
                }

              if (show_statuscodes && ok_str != NULL && hp[index].sc != NULL)
                {
                  scdummy = strchr(hp[index].sc, ' ');
                  if (scdummy) *scdummy = 0x00;

                  if (strstr(ok_str, hp[index].sc) == NULL)
                    {
                      hp[index].ok--;
                      hp[index].err++;
                    }
                }

              hp[index].header_len = 0;
              free(hp[index].sc);
              fflush(NULL);
              if (curncount != count && !stop)
                hp[index].wait = get_ts() + wait;
            }// end state 4
        }// for select

      if (!wait_read && !n_partial_write && !n_partial_read && curncount != count && !stop)
        usleep((useconds_t)(wait * 1000000.0));

    }// for while

  for(index = 0; index < n_hosts; index++)
    {
      if (hp[index].ok){
        hp[index].avg_httping_time = hp[index].avg / (double)hp[index].ok;
        ok++;
      }
      else
        hp[index].avg_httping_time = -1.0;

      double total_took = get_ts() - started_at;
      if (!quiet && !machine_readable && !nagios_mode)
        {
          printf("--- %s ping statistics ---\n", hp[index].name);

          if (hp[index].curncount == 0 && hp[index].err > 0)
            fprintf(stderr, "internal error! (curncount)\n");

          if (count == -1)
            printf("%d connects, %d ok, %3.2f%% failed, time %.0fms\n", hp[index].curncount, hp[index].ok, (((double)hp[index].err) / ((double)hp[index].curncount)) * 100.0, total_took * 1000.0);
          else
            printf("%d connects, %d ok, %3.2f%% failed, time %.0fms\n", hp[index].curncount, hp[index].ok, (((double)hp[index].err) / ((double)count)) * 100.0, total_took * 1000.0); //FIXME: count

          if (hp[index].ok > 0)
            {
              printf("round-trip min/avg/max = %.1f/%.1f/%.1f ms\n", hp[index].min, hp[index].avg_httping_time, hp[index].max);

              if (show_Bps)
                printf("Transfer speed: min/avg/max = %d/%d/%d KB\n", hp[index].Bps_min / 1024, (int)(hp[index].Bps_avg / hp[index].ok) / 1024, hp[index].Bps_max / 1024);
            }
        }
    }

  ok = 0;
  type_err = 0;
  freeaddrinfo(ai);
  free(buffer);

  for(index = 0; index < n_hosts; index++)
    {
      ph_free(&hp[index].ph);
      free(hp[index].name);
      if (hp[index].header != NULL)
        free(hp[index].header);

      if(type_err != 0) //there was at least one error
        continue;

      if (nagios_mode == 1)
        {
          if (hp[index].ok == 0) //connection not valid
            continue;
          else if (hp[index].avg_httping_time >= nagios_crit)
              type_err = 2;
          else if (hp[index].avg_httping_time >= nagios_warn)
              type_err = 1;
          ok = 1; // one valid connection
        }
      else if (nagios_mode == 2)
        {
          if (hp[index].ok && last_error[0] == 0x00)
            type_err = 0;
          else
            type_err = 1;
        }
      else if(hp[index].ok)
        ok = 1;
    }

  free(hp);

  if (nagios_mode == 1)
    {
      if (!ok)
        {
          printf("CRITICAL - all connections have failed: %s", last_error);
          return 2;
        }

      switch(type_err)
        {
        case 1:
          printf("WARNING - average httping-time is %.1f\n", hp[index].avg_httping_time);
          return 1;
        case 2:
          printf("CRITICAL - average httping-time is %.1f\n", hp[index].avg_httping_time);
          return 2;
        default: /* OK */
          printf("OK - average httping-time is %.1f (%s)|ping=%f\n", hp[index].avg_httping_time, last_error, hp[index].avg_httping_time);
          break;
        }
    }
  else if (nagios_mode == 2)
    {
      switch(type_err)
        {
        case 0:
          printf("OK - all fine, avg httping time is %.1f|ping=%f\n", hp[index].avg_httping_time, hp[index].avg_httping_time);
          break;
        default:
          printf("%s: - failed: %s", nagios_exit_code == 1?"WARNING":(nagios_exit_code == 2?"CRITICAL":"ERROR"), last_error);
          return nagios_exit_code;
        }
    }

  if (ok)
    return 0;
  else
    return 127;
}
