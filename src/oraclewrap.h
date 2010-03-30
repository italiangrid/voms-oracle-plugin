/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2002-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
