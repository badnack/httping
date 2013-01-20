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

typedef struct ping_buffer ping_buffer;

struct ping_buffer{
  int size;
  int to_read;
  int to_write;
  int r_pnt;
  int w_pnt;
  char buf[0];
};

ping_buffer* create_buffer(int);
void spprintf(ping_buffer* pb, char* fmt, ...);
void spcat(ping_buffer* pb, char* fmt, ...);