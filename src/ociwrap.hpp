/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - valerio.venturi@cnaf.infn.it
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

#include <oci.h>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include "dbwrap.h"

extern "C"
{
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/x509.h>
#include <string.h>
}

static pthread_mutex_t table_access = PTHREAD_MUTEX_INITIALIZER;

struct datum 
{
  OCISvcCtx * svc;
  time_t      currtime;
};

struct binder {
  void   *address;
  size_t  size;
  int     type;
  sb2     is_null;
};

class MyException : public std::runtime_error
{

public:
  
  MyException(std::string const & msg, int c) :
    std::runtime_error(msg),
    code(c)
  {}

  int Code()
  {
    return code;
  }

  const char * what() const throw()
  {
    const char * old = runtime_error::what();
    char * s = (char *)malloc(strlen(old) + 6);
    sprintf(s, "%.5ld", code);
    strcat(s, old);
    return s;
  }
  
private:

  int code;
  
};

class Session
{

public:

  Session(OCISvcCtx * svc,
          OCIError * err,
          int dbVersion,
          bool insec,
          OCIEnv *env);
  
  ~Session();
  
  bool execute_query(void *h, OCIStmt **stmt_out, const char *query, int numParams, binder *binders);
  std::string getError();
  void setError(bool oracle, std::string message="", OCIStmt *stmt = NULL);
  bool operationGetDBVersion(int *ver);
  bool operationGetUID(X509 *cert, signed long int *uid);
  bool operationGetAll(signed long int uid, std::vector<std::string>& fqans);
  bool operationGetGroupAndRoleAttribs(signed long int uid, char *group,
                                       char *role, 
                                       std::vector<gattrib> &attrs);
  bool operationGetGroupAttribs(signed long int uid, std::vector<gattrib> &attrs);
  bool operationGetRoleAttribs(signed long int uid, const char *role,
                               std::vector<gattrib> &attrs);
  bool operationGetAllAttribs(signed long int uid, std::vector<gattrib> &attrs);
  bool operationGetGroups(signed long int uid, std::vector<std::string> &fqans);
  bool operationGetRoles(signed long int uid, std::vector<std::string> &fqans, const char* role);
  bool operationGetGroupsAndRole(signed long int uid, std::vector<std::string> &fqans,
                                 const char *group, const char *role);
  bool bindParameters(void *h, OCIStmt *stmt, int numParams, binder *binders);
  bool getFQANs(const char *query, int numparams, binder *binders, std::vector<std::string> &fqans);
  bool getAttributes(const char *query, int numparams, binder *binders, std::vector<gattrib> &attrs);

  int dbVersion;
 
private:
  
  int getErrorDetails(sword res,
                      std::string &msg);
  
  OCISvcCtx *  service;
  OCIError    *  error;
  OCIEnv *env;
  int insecure;
  sword res;
  std::string errorstring;
};

class SessionFactory
{

public:

  SessionFactory();

  void init(const std::string& contact, 
            const std::string& username,
            const std::string& password,
            int minConnections = 10, 
            int maxConnections = 100,
            int incConnections = 5);

  ~SessionFactory();

  int CreateSession();

  void DestroySession(int session);

  void Clean();

  void Destroy();

  void changeSessionId(int oldId, int newId);

  Session GetSession(int session);

  int dbVersion;
  bool insecure;

private:
  
  int getErrorDetails(sword res,
                      std::string &msg);

  OCIEnv *   environment;
  OCIError * error;
  OCISPool * pool;
  char *     pool_name;
  int        pool_name_len;

  std::string username;
  std::string password;
  
  std::map<int, datum> connections;
  int                  currentpos;

};
