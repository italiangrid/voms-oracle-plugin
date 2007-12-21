/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003, 2004, 2005 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

extern "C" {
#include <sys/types.h>
#include <unistd.h>
}

#include "dbwrap.h"
#include <vector>
#include <string>


namespace bsq {

class orinterface;

class orinterface : public sqliface::interface 
{
 public:
  
  orinterface();
  ~orinterface();
  int error(void) const;
  bool connect(const char *, const char *, const char *, const char *);
  bool reconnect();
  void close(void);
  bool setOption(int option, void *value);

  bool operation(int operation_type, void *result, ...);

  bool isConnected(void);
  char *errorMessage(void);

  interface *getSession();
  void releaseSession(interface *);

 private:
  
  orinterface(const orinterface &);

  bool read_wrap(int, std::string&);
  bool write_wrap(int, const std::string&);
  int setup_connection();
  void setError(const std::string &);
  void setError(int, const std::string &);
  bool initialize_conn(const char *, const char *, const char *, const char *);
  std::string make_conn(const char *, const char *, const char *, const char *,
                        int *);

  int   err;
  std::string handle;
  int   dbVersion;
  std::string errorString;
  char *dbname;
  char *hostname;
  char *user;
  const char *password;
  bool connected;
  bool insecure;
  pid_t middlemanpid;
};

} // namespace bsq
