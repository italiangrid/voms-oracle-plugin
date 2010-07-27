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

#include "ociwrap.hpp"
#include <vector>
#include <stdio.h>

static char *normalize(char * candidate);

void *CreateBlocks()
{
  return new std::vector<void *>;
}

void *GetBlock(void *h, int len)
{
  std::vector<void *> *v = ((std::vector<void *> *)h);

  void *mem = malloc(len);

  v->push_back(mem);
  return mem;
}

void FreeBlocks(void *h)
{
  std::vector<void *> *v = ((std::vector<void *> *)h);

  for (std::vector<void *>::iterator i = v->begin(); i != v->end(); i++)
    free(*i);
  delete v;
}

Session::Session(OCISvcCtx * svc,
                 OCIError * err,
                 int dbV,
                 bool insec,
                 OCIEnv *_env) :
  service(svc),
  error(err),
  dbVersion(dbV),
  insecure(insec),
  env(_env)
{
}
  
Session::~Session()
{
}
  

bool Session::execute_query(void *h, OCIStmt **stmt_out, const char *query, int numParams, binder *binders)
{
  OCIStmt *stmt = NULL;

  // prepare the statement
  if (OCI_SUCCESS != OCIStmtPrepare2(service,
                                     &stmt,
                                     error,
                                     (text *)query, strlen(query)+1,
                                     0, 0, 
                                     OCI_NTV_SYNTAX,
                                     OCI_DEFAULT))
    goto err;

  if (!bindParameters(h, stmt, numParams, binders))
    goto err;

  // execute
  if (OCI_SUCCESS != (res = OCIStmtExecute(service,
                                          stmt,
                                          error,
                                          0,
                                          0,
                                          (OCISnapshot *) 0,
                                          (OCISnapshot *) 0,
                                           OCI_STMT_SCROLLABLE_READONLY)))
    goto err;

  *stmt_out = stmt;
  return true;

err:
  setError(true, std::string("Preparing : ") + query);

  if (stmt)
    // free the statement
    (void)OCIStmtRelease(stmt,
                         error,
                         NULL,
                         0,
                         OCI_DEFAULT);
  return false;
}


std::string Session::getError()
{
  return errorstring;
}

void Session::setError(bool oracle, std::string message, OCIStmt *stmt)
{
  std::string msg="";
  text buffer[512];
  sb4 code = 0;
  char buf[10];

  if (oracle) {
    switch (res) {
    case OCI_NO_DATA:
      msg = "000000OCI_NO_DATA ";
      break;
  
    case OCI_INVALID_HANDLE:
    case OCI_ERROR:
      OCIErrorGet(error, 1, 0, &code, buffer, 512, OCI_HTYPE_ERROR);
      sprintf(buf, "%.5ld", code);
      msg = std::string(buf) + reinterpret_cast<char*>(buffer) + " ";
      break;
    default:
      msg = "000000Unknown error code ";
    }
  }

  if (stmt) {
    text *value = NULL;
    ub4 len = 0;
    OCIAttrGet(stmt, OCI_HTYPE_STMT, (dvoid **)&value, &len, OCI_ATTR_STATEMENT, error);
    msg += std::string((char *)value) + " ";
  }

  errorstring = msg + message;
}

bool Session::operationGetDBVersion(int *ver)
{
  const char *query = "SELECT version FROM version";
  bool result = false;

  OCIStmt *stmt = NULL;

  void *h = CreateBlocks();
  if (!h)
    return false;

  if (execute_query(h, &stmt, query, 0, NULL)) {
    OCIDefine *defnpp = (OCIDefine *)0;

    if (res = OCIDefineByPos(stmt, &defnpp, error, 1, ver, sizeof(int), SQLT_INT,
                       NULL, (ub2*) 0, (ub2*)0, OCI_DEFAULT) == OCI_SUCCESS) {
      res = OCIStmtFetch2(stmt, error, (ub4)1, OCI_FETCH_NEXT, (sb4)0, OCI_DEFAULT);
      if (res == OCI_SUCCESS)
        result = true;
      else
        setError(true);
    }
    OCIStmtRelease(stmt, error, NULL, 0, OCI_DEFAULT);
  }

  FreeBlocks(h);
  return result;
}

bool Session::operationGetUID(X509 *cert, signed long int *uid)
{
  X509_NAME *subject = X509_get_subject_name(cert);
  X509_NAME *issuer  = X509_get_issuer_name(cert);
  char *caname = NULL;
  char *subjname = NULL;
  unsigned char *buffersubj = NULL;
  unsigned char *realpointersubj = NULL;
  unsigned char *bufferiss = NULL;
  unsigned char *realpointeriss = NULL;
  const char *query = NULL;
  const char *reason = NULL;
  bool result = false;

  signed long int cid = -1;
  boolean suspended = false;
  OCIStmt *stmt = NULL;

  OCIBind *bind1 = NULL,
    *bind2 = NULL;

  OCILobLocator *isslob = NULL;
  OCILobLocator *onelob = NULL;

  if (stmt)
    OCIStmtRelease(stmt, error, NULL, 0, OCI_DEFAULT);
  stmt = NULL;

  if (!insecure) {

    /* dbVersion == 2 or old table */
    query = (dbVersion == 3 ?
             "SELECT cid FROM ca WHERE subject_string = :1" :
             "SELECT cid FROM ca WHERE ca.ca = :1");

    if (OCI_SUCCESS == (res = OCIStmtPrepare2(service, &stmt, error, 
                                              (text*)query, strlen(query), 0, 0,
                                              OCI_NTV_SYNTAX, OCI_DEFAULT))) {
      caname = normalize(X509_NAME_oneline(issuer, NULL, 0));
      if (!caname)
        goto err;

      if (OCI_SUCCESS != (res = OCIBindByPos(stmt, &bind1, error, 1, caname, 
                                             strlen(caname) +1, SQLT_STR, 0, 0, 0, 0, 0,
                                             OCI_DEFAULT))) {
        free(caname);
        goto err;
      }
      if (OCI_SUCCESS == (res = OCIStmtExecute(service, stmt, error, 0, 0, 0, 0,
                                               OCI_STMT_SCROLLABLE_READONLY))) {
        OCIDefine* defnpp = (OCIDefine *)0;
        if (OCI_SUCCESS != (res = OCIDefineByPos(stmt, &defnpp, error, 1, &cid,
                                                 sizeof(cid), SQLT_INT, 0, 0, 0,
                                                 OCI_DEFAULT)))
          goto err;

        if (OCI_SUCCESS != (res = OCIStmtFetch2(stmt, error, 1, OCI_FETCH_NEXT, 0,
                                                OCI_DEFAULT)))
          goto err;
      }
      else
        goto err;
    }
  }

  if (stmt)
    OCIStmtRelease(stmt, error, NULL, 0, OCI_DEFAULT);
  stmt = NULL;
     
  bind1 = NULL;
  /* now get uid */
        
  query = (dbVersion == 3 ? 
           (insecure ? "SELECT usr_id FROM certificate WHERE subject_string = :1 AND suspended = 0" :
            "SELECT usr_id FROM certificate WHERE subject_string = :1 AND ca_id = :2 AND suspended = 0") :
           (insecure ? "SELECT userid FROM usr WHERE usr.dn = :1" :
            "SELECT userid FROM usr WHERE usr.dn = :1 and ca = :2"));

  reason = (dbVersion == 3 ? 
            (insecure ? "SELECT suspended_reason FROM certificate WHERE subject_string = :1 AND suspended != 0" :
             "SELECT suspended_reason FROM certificate WHERE subject_string = :1 AND ca_id = :2 AND suspended != 0") :
            NULL);


  if (OCI_SUCCESS == (res = OCIStmtPrepare2(service, &stmt, error, 
                                            (text*)query, strlen(query), 0, 0,
                                            OCI_NTV_SYNTAX, OCI_DEFAULT))) {
    subjname = normalize(X509_NAME_oneline(subject, NULL, 0));
    if (!subjname)
      goto err;

    if (OCI_SUCCESS != (res = OCIBindByPos(stmt, &bind1, error, 1, subjname, 
                                           strlen(subjname) +1, SQLT_STR, 0, 0, 0, 0, 0,
                                           OCI_DEFAULT)))
      goto err;

    if (!insecure)
      if (OCI_SUCCESS != (res = OCIBindByPos(stmt, &bind2, error, 2, &cid, sizeof(cid),
                                             SQLT_INT, 0, 0, 0, 0, 0, OCI_DEFAULT)))
        goto err;

    if (OCI_SUCCESS == (res = OCIStmtExecute(service, stmt, error, 0, 0, 0, 0,
                                             OCI_STMT_SCROLLABLE_READONLY))) {
      OCIDefine* defnpp = (OCIDefine *)0;
      if (OCI_SUCCESS != (res = OCIDefineByPos(stmt, &defnpp, error, 1, uid,
                                               sizeof(*uid), SQLT_INT, 0, 0, 0,
                                               OCI_DEFAULT)))
        goto suspendederr;
      if (OCI_SUCCESS == (res = OCIStmtFetch2(stmt, error, 1, OCI_FETCH_NEXT, 0,
                                              OCI_DEFAULT)))
        result = true;
      goto suspendederr;
    }
    else
      goto suspendederr;
  }

  /* Determine suspension reason */
suspendederr:
  if (OCI_SUCCESS == (res = OCIStmtPrepare2(service, &stmt, error, 
                                            (text*)reason, strlen(reason), 0, 0,
                                            OCI_NTV_SYNTAX, OCI_DEFAULT))) {

    if (OCI_SUCCESS != (res = OCIBindByPos(stmt, &bind1, error, 1, subjname, 
                                           strlen(subjname) +1, SQLT_STR, 0, 0, 0, 0, 0,
                                           OCI_DEFAULT)))
      goto err;

    if (!insecure)
      if (OCI_SUCCESS != (res = OCIBindByPos(stmt, &bind2, error, 2, &cid, sizeof(cid),
                                             SQLT_INT, 0, 0, 0, 0, 0, OCI_DEFAULT)))
        goto err;

    if (OCI_SUCCESS == (res = OCIStmtExecute(service, stmt, error, 0, 0, 0, 0,
                                             OCI_STMT_SCROLLABLE_READONLY))) {
      OCIDefine* defnpp = (OCIDefine *)0;
      OCIParam *colhd = NULL;
      int len;
      text *buffer;
      sb2 indicator;

      if (OCI_SUCCESS != OCIParamGet((dvoid*)stmt, (ub4)OCI_HTYPE_STMT, error,
                                     (dvoid **)&colhd, (ub4)1))
        goto err;

      if (OCI_SUCCESS != OCIAttrGet((dvoid*)colhd, (ub4)OCI_DTYPE_PARAM,
                                    (dvoid*)&len, NULL, (ub4)OCI_ATTR_DATA_SIZE,
                                    error))
        goto err;

      void *h = CreateBlocks();
      buffer = (text*)GetBlock(h, len+1);
      if (OCI_SUCCESS != (res = OCIDefineByPos(stmt, &defnpp, error, 1, 
                                               (dvoid*)buffer, len, SQLT_STR,
                                               (dvoid*)&indicator, 0, 0,
                                               OCI_DEFAULT)))
        {
          FreeBlocks(h);
          goto err;
        }
      if (OCI_SUCCESS == (res = OCIStmtFetch2(stmt, error, 1, OCI_FETCH_NEXT, 0,
                                              OCI_DEFAULT))) {
        setError(false, "00011" + std::string((char*)buffer, (int)len));
        FreeBlocks(h);
        result = false;
        goto end;
      }
      else {
        FreeBlocks(h);
        goto err;
      }
    }
    else
      goto err;
  }
 
  err:

  if (res != OCI_SUCCESS) {
    setError(true, std::string("1 = '") + subjname + "]), 2 = '" , stmt);
  }
  else if (!result)
    setError(false, "Out of memory.");

 end:
  if (stmt)
    OCIStmtRelease(stmt, error, NULL, 0, OCI_DEFAULT);
  if (caname)
    free(caname);
  if (subjname)
    free(subjname);
  if (realpointersubj)
    free(realpointersubj);
  if (realpointeriss)
    free(realpointeriss);
  if (onelob)
    OCIDescriptorFree(onelob, OCI_DTYPE_LOB);
  if (isslob)
    OCIDescriptorFree(isslob, OCI_DTYPE_LOB);
  return result;
}

bool Session::operationGetAll(signed long int uid, std::vector<std::string>& fqans)
{
  const char *query = "SELECT groups.dn, role FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "m.userid = :1";

  struct binder params[1];

  params[0].address = &uid;
  params[0].size    = sizeof(uid);
  params[0].type    = SQLT_INT;
  params[0].is_null = 0;

  return getFQANs(query, 1, params, fqans);
}

bool Session::operationGetGroupAndRoleAttribs(signed long int uid, char *group,
                                              char *role, 
                                              std::vector<gattrib> &attrs)
{
  const char *query1 = "SELECT attributes.a_name, usr_attrs.a_value, NULL, NULL "
    "FROM attributes, usr_attrs "
    "WHERE attributes.a_id = usr_attrs.a_id AND "
    "usr_attrs.u_id = :1";

  const char *query2 = "SELECT attributes.a_name, group_attrs.a_value, groups.dn, NULL "
    "FROM attributes, group_attrs, groups, m "
    "WHERE attributes.a_id = group_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = :1 AND "
    "m.rid is NULL AND "
    "group_attrs.g_id = m.gid";

  const char *query3 = "SELECT attributes.a_name, role_attrs.a_value, groups.dn, roles.role "
    "FROM attributes, role_attrs, groups, roles, m "
    "WHERE attributes.a_id = role_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = :1 AND "
    "m.rid = roles.rid AND "
    "roles.role = :2 AND "
    "groups.dn = :3 AND "
    "role_attrs.g_id = m.gid AND "
    "role_attrs.r_id = m.rid";

  struct binder params[3];

  params[0].address = &uid;
  params[0].size    = sizeof(uid);
  params[0].type    = SQLT_INT;
  params[0].is_null = 0;
  params[1].address = role;
  params[1].size    = strlen(role) +1;
  params[1].type    = SQLT_STR;
  params[1].is_null = 0;
  params[2].address = group;
  params[2].size    = strlen(group) +1;
  params[2].type    = SQLT_STR;
  params[2].is_null = 0;

  return getAttributes(query1, 1, params, attrs) &
    getAttributes(query2, 1, params, attrs) &
    getAttributes(query3, 3, params, attrs);
}

bool Session::operationGetGroupAttribs(signed long int uid, std::vector<gattrib> &attrs)
{
  const char *query1 = "SELECT attributes.a_name, usr_attrs.a_value, NULL, NULL "
    "FROM attributes, usr_attrs "
    "WHERE attributes.a_id = usr_attrs.a_id AND "
    "usr_attrs.u_id = :1";

  const char *query2 = "SELECT attributes.a_name, group_attrs.a_value, groups.dn, NULL "
    "FROM attributes, group_attrs, groups, m "
    "WHERE attributes.a_id = group_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = :1 AND "
    "m.rid is NULL AND "
    "group_attrs.g_id = m.gid";

  struct binder params[1];

  params[0].address = &uid;
  params[0].size    = sizeof(uid);
  params[0].type    = SQLT_INT;
  params[0].is_null = 0;

  return getAttributes(query1, 1, params, attrs) &
    getAttributes(query2, 1, params, attrs);
}


bool Session::operationGetRoleAttribs(signed long int uid, const char *role,
                                      std::vector<gattrib> &attrs)
{
  const char *query1 = "SELECT attributes.a_name, usr_attrs.a_value, NULL, NULL "
    "FROM attributes, usr_attrs "
    "WHERE attributes.a_id = usr_attrs.a_id AND "
    "usr_attrs.u_id = :1";

  const char *query2 = "SELECT attributes.a_name, role_attrs.a_value, groups.dn, roles.role "
    "FROM attributes, role_attrs, roles, groups, m "
    "WHERE m.gid = groups.gid AND "
    "roles.rid = m.rid AND "
    "groups.gid = role_attrs.g_id AND "
    "attributes.a_id = role_attrs.a_id AND "
    "role_attrs.r_id = roles.rid AND "
    "m.userid = :1 and roles.role = :2";

  struct binder params[2];

  params[0].address = &uid;
  params[0].size    = sizeof(uid);
  params[0].type    = SQLT_INT;
  params[0].is_null = 0;
  params[1].address = (void*)role;
  params[1].size    = strlen(role) +1;
  params[1].type    = SQLT_STR;
  params[1].is_null = 0;

  return getAttributes(query1, 1, params, attrs) &
    getAttributes(query2, 2, params, attrs) &
    operationGetGroupAttribs(uid, attrs);
}


bool Session::operationGetAllAttribs(signed long int uid, std::vector<gattrib> &attrs)
{
  const char *query1 = "SELECT attributes.a_name, usr_attrs.a_value, NULL, NULL "
    "FROM attributes, usr_attrs "
    "WHERE attributes.a_id = usr_attrs.a_id AND "
    "usr_attrs.u_id = :1";

  const char *query2 = "SELECT attributes.a_name, group_attrs.a_value, groups.dn, NULL "
    "FROM attributes, group_attrs, groups, m "
    "WHERE attributes.a_id = group_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = :1 AND "
    "m.rid is NULL AND "
    "group_attrs.g_id = m.gid";

  const char *query3 = "SELECT attributes.a_name, role_attrs.a_value, groups.dn, roles.role "
    "FROM attributes, role_attrs, groups, roles, m "
    "WHERE attributes.a_id = role_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = :1 AND "
    "m.rid = roles.rid AND "
    "role_attrs.g_id = m.gid AND "
    "role_attrs.r_id = m.rid";

  struct binder params[1];

  params[0].address = &uid;
  params[0].size    = sizeof(uid);
  params[0].type    = SQLT_INT;
  params[0].is_null = 0;

  return getAttributes(query1, 1, params, attrs) &
    getAttributes(query2, 1, params, attrs) &
    getAttributes(query3, 1, params, attrs);
}

bool Session::operationGetGroups(signed long int uid, std::vector<std::string> &fqans)
{
  const char *query = "SELECT groups.dn, NULL FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "m.userid = :1";

  struct binder params[1];

  params[0].address = &uid;
  params[0].size    = sizeof(uid);
  params[0].type    = SQLT_INT;
  params[0].is_null = 0;

  return getFQANs(query, 1, params, fqans);
}

bool Session::operationGetRoles(signed long int uid, std::vector<std::string> &fqans, const char* role)
{
  const char *query =     "SELECT groups.dn, role FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "roles.role = :1 AND m.userid = :2";

  struct binder params[2];

  params[0].address = (void*)role;
  params[0].size    = strlen(role) +1;
  params[0].type    = SQLT_STR;
  params[0].is_null = 0;
  params[1].address = &uid;
  params[1].size    = sizeof(uid);
  params[1].type    = SQLT_INT;
  params[1].is_null = 0;
  
  return getFQANs(query, 2, params, fqans) &
    operationGetGroups(uid, fqans);
}

bool Session::operationGetGroupsAndRole(signed long int uid, std::vector<std::string> &fqans,
                                        const char *group, const char *role)
{
  const char *query =     "SELECT groups.dn, role FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "groups.dn = :1 AND roles.role = :2 AND "
    "m.userid = :3";

  struct binder params[3];

  params[0].address = (void*)group;
  params[0].size    = strlen(group) +1;
  params[0].type    = SQLT_STR;
  params[0].is_null = 0;
  params[1].address = (void*)role;
  params[1].size    = strlen(role) +1;
  params[1].type    = SQLT_STR;
  params[1].is_null = 0;
  params[2].address = &uid;
  params[2].size    = sizeof(uid);
  params[2].type    = SQLT_INT;
  params[2].is_null = 0;
  
  return getFQANs(query, 3, params, fqans) &
    operationGetGroups(uid, fqans);

}

bool Session::bindParameters(void *h, OCIStmt *stmt, int numParams, binder *binders)
{
  sword res;

  for (int i = 0; i< numParams; i++) {
    OCIBind **bind = (OCIBind **)GetBlock(h, sizeof(OCIBind *));
    if (!bind)
      return false;

    res = OCIBindByPos(stmt, bind, error, i+1 /* position */, binders[i].address, 
                       binders[i].size,  binders[i].type, &binders[i].is_null, 0,
                       0, 0, 0, OCI_DEFAULT);
    if (res != OCI_SUCCESS)
      return false;
  }
    
  return true;
}


bool Session::getFQANs(const char *query, int numparams, binder *binders, std::vector<std::string> &fqans)
{
  OCIStmt *stmt = NULL;

  void *h = CreateBlocks();
  if (!h)
    return false;

  if (execute_query(h, &stmt, query, numparams, binders)) {
    /* The query has been succesfully executed.  Now retrieve the data. */


    // column buffer
    int limit =  256;
    text * s = (text *)malloc(limit + 1);
    
    res = OCI_SUCCESS;

    while(res != OCI_NO_DATA) {
      std::string sizes;
      std::string fields;
      text *buffer[3];
      sb2 indicator[3];
      int lens[3];
      OCIParam *colhd = NULL;

      // go through columns
      for(int i = 1; i <= 2; ++i) {
        int len = 0;
        // put on the i-th column
        colhd = (OCIParam *)0;
        if(res = OCIParamGet((dvoid *)stmt, (ub4)OCI_HTYPE_STMT,
                       error,
                       (dvoid **)&colhd, 
                       (ub4)i) != OCI_SUCCESS)
          {}    
        
        // get length of the field
        if(res = OCIAttrGet((dvoid*)colhd, (ub4)OCI_DTYPE_PARAM,
                      (dvoid*)&len, NULL, (ub4)OCI_ATTR_DATA_SIZE,
                      (OCIError *) error) != OCI_SUCCESS) 
          {}    
  
        lens[i] = len;
        buffer[i] =(text*)GetBlock(h, lens[i]+1);

        // bind
        OCIDefine* defnpp = (OCIDefine *)0;
        if(res = OCIDefineByPos(stmt,
                                &defnpp,
                                error,
                                i, 
                                (dvoid *)(buffer[i]), (sb4)(lens[i])+1, SQLT_STR,
                                (dvoid *)(&(indicator[i])), (ub2 *)0, (ub2 *)0,
                                OCI_DEFAULT) != OCI_SUCCESS)
          {}
      }

      // fetch
      res = OCIStmtFetch2(stmt,
                             error,
                             (ub4)1,
                             OCI_FETCH_NEXT,
                             (sb4)0,
                             OCI_DEFAULT);
        
      if(res == OCI_NO_DATA) {
        OCIDescriptorFree(colhd,
                          OCI_DTYPE_PARAM);
        break;
      }

      if(res != OCI_SUCCESS) {

        OCIDescriptorFree(colhd,
                          OCI_DTYPE_PARAM);
        break;
      }
      
      // NULL values
      std::string fqan = std::string((char *)(buffer[1])) + 
        ((indicator[2] == -1 || strlen((char*)(buffer[2])) == 0) ?
         "" :
         "/Role=" + std::string((char *)(buffer[2])));

      // put in vector
      if(res != OCI_NO_DATA)
        fqans.push_back(fqan);
    }

    if (res != OCI_NO_DATA)
      setError(true);
    
    FreeBlocks(h);

    // free the statement
    OCIStmtRelease(stmt,
                   error,
                   NULL,
                   0,
                   OCI_DEFAULT);
  }
  else {
    setError(true);
    return false;
  }

  if (fqans.size() == 0)
    return false;

  if (res == OCI_NO_DATA)
    return true;

  return false;
}

static char *normalize(char * candidate)
{
  std::string name = std::string(candidate);

  std::string::size_type pos = name.find(std::string("/USERID="));
  while (pos != std::string::npos) {
    name = name.substr(0, pos) + "/UID=" + name.substr(pos+8);
    pos = name.find("/USERID=", pos+1);
  }

  pos = name.find(std::string("/emailAddress="));
  while (pos != std::string::npos) {
    name = name.substr(0, pos) + "/Email=" + name.substr(pos+14);
    pos = name.find("/emailAddress=", pos+1);
  }

  pos = name.find(std::string("/E="));
  while (pos != std::string::npos) {
    name = name.substr(0, pos) + "/Email=" + name.substr(pos+3);
    pos = name.find("/USERID=", pos+1);
  }

  char *out = strdup(name.c_str());

  free(candidate);

  return out;
}

bool Session::getAttributes(const char *query, int numparams, binder *binders, std::vector<gattrib> &attrs)
{
  OCIStmt *stmt;

  void *h = CreateBlocks();
  if (!h)
    return false;
  
  if (execute_query(h, &stmt, query, numparams, binders)) {
    /* The query has been succesfully executed.  Now retrieve the data. */


    // column buffer
    int limit =  256;
    text * s = (text *)malloc(limit + 1);
    
    res = OCI_SUCCESS;

    while(res != OCI_NO_DATA) {
      std::string sizes;
      std::string fields;
      text *buffer[5];
      sb2 indicator[5];
      int lens[5];
      OCIParam *colhd = NULL;

      // go through columns
      for(int i = 1; i <= 4; ++i) {
        // put on the i-th column
        colhd = (OCIParam *)0;
        if(res = OCIParamGet((dvoid *)stmt, (ub4)OCI_HTYPE_STMT,
                       error,
                       (dvoid **)&colhd, 
                       (ub4)i) != OCI_SUCCESS)
          {}    
        
        // get length of the field
        int len = 0;
        if(res = OCIAttrGet((dvoid*)colhd, (ub4)OCI_DTYPE_PARAM,
                      (dvoid*)&len, NULL, (ub4)OCI_ATTR_DATA_SIZE,
                      (OCIError *) error) != OCI_SUCCESS) 
          {}    
  
        lens[i] = len;
        buffer[i] =(text*)GetBlock(h, lens[i]+1);

        // bind
        OCIDefine* defnpp = (OCIDefine *)0;
        if(res = OCIDefineByPos(stmt,
                          &defnpp,
                          error,
                          i, 
                                (dvoid *)(buffer[i]), (sb4)(lens[i]+1), SQLT_STR,
                                (dvoid *)(&(indicator[i])), (ub2 *)0, (ub2 *)0,
                          OCI_DEFAULT) != OCI_SUCCESS)
          {}
      }

      // fetch
      res = OCIStmtFetch2(stmt,
                             error,
                             (ub4)1,
                             OCI_FETCH_NEXT,
                             (sb4)0,
                             OCI_DEFAULT);
        
      if(res == OCI_NO_DATA) {
        OCIDescriptorFree(colhd,
                          OCI_DTYPE_PARAM);
        break;
      }

      if(res != OCI_SUCCESS) {
        OCIDescriptorFree(colhd,
                          OCI_DTYPE_PARAM);
        break;
      }
      
      // NULL values
      gattrib ga;

      ga.name = std::string((char *)(buffer[1]));
      ga.value = (indicator[2] == -1 || strlen((char *)(buffer[2])) == 0 ? "" :
                  std::string((char *)(buffer[2])));
      ga.qualifier  = (indicator[3] == -1 || strlen((char *)(buffer[3])) == 0 ? 
                       "" : std::string((char *)(buffer[3])));

      if ((indicator[4] != -1 ) && (strlen((char *)(buffer[4])) != 0))
        ga.qualifier += "/Role="+(std::string((char *)(buffer[4])));

      attrs.push_back(ga);
      
      OCIDescriptorFree(colhd,
                        OCI_DTYPE_PARAM);
    }
    
    FreeBlocks(h);

    if (res != OCI_NO_DATA)
      setError(true);

    // free the statement
    OCIStmtRelease(stmt,
                   error,
                   NULL,
                   0,
                   OCI_DEFAULT);

    return (res == OCI_NO_DATA);
  }
  
  return false;
}

int Session::getErrorDetails(sword res,
                             std::string &msg)
{
  sb4 code;
  text buffer[512];

  switch (res)
  {
  case OCI_NO_DATA:
    msg = "OCI_NO_DATA";
    return 0;
    break;
  
  case OCI_ERROR:
    OCIErrorGet(error, 1, 0, &code, buffer, 512, OCI_HTYPE_ERROR);
    msg = std::string("F ") + reinterpret_cast<char*>(buffer);
    return static_cast<int>(code);
    break;
  
  case OCI_INVALID_HANDLE:
    msg = "OCI_INVALID_HANDLE";
    return 0;
    break;
  
  default:
    msg = "Unknown error code";
    return 0;
  }
}
  
SessionFactory::SessionFactory() :
  dbVersion(-1),
  insecure(false),
  environment((OCIEnv *)0),
  error((OCIError *)0),
  pool((OCISPool *)0),
  pool_name(0),
  pool_name_len(0),
  currentpos(0)
{
}
    
void SessionFactory::init(const std::string& contact,
                          const std::string& username,
                          const std::string& password,
                          int minConnections,
                          int maxConnections,
                          int incConnections)
{
  this->username = username;
  this->password = password;
    
  sword res;

  // create oracle environment
  if (OCIEnvCreate(&environment,
                   OCI_THREADED,
                   (dvoid **)0, 0, 0, 0,
                   (size_t)0,
                   (dvoid **)0) != OCI_SUCCESS)
  {
    sb4 code;
    text buffer[512];    
    OCIErrorGet(environment, 1, 0, &code, buffer, 512, OCI_HTYPE_ERROR);
    throw MyException(std::string("OCIEnvCreate: ") + reinterpret_cast<char*>(buffer), static_cast<int>(code));
  }
  
  // allocate error handle
  if (OCIHandleAlloc((dvoid *)environment,
                     (dvoid **)&error, 
                     OCI_HTYPE_ERROR, 
                     (size_t)0,
                     (dvoid **)0) != OCI_SUCCESS)
  {
    // should free env
    sb4 code;
    text buffer[512];    
    OCIErrorGet(environment, 1, 0, &code, buffer, 512, OCI_HTYPE_ERROR);
    throw MyException(std::string("OCIHandlAlloc ") +reinterpret_cast<char*>(buffer), static_cast<int>(code));
  }
  
  // connection pool handle
  res = OCIHandleAlloc((dvoid *)environment, 
                       (dvoid **)&pool, 
                       OCI_HTYPE_SPOOL, 
                       (size_t)0, 
                       (dvoid **)0);

  if(res != OCI_SUCCESS)
  {
    // should free env and err
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException(std::string("OCIHandlAlloc (2)") +msg, code);
  }

  // create connection pool
  res = OCISessionPoolCreate((OCIEnv *)environment,
                             (OCIError *)error, 
                             (OCISPool *)pool,
                             (text **)&pool_name, (ub4 *)&pool_name_len,
                             (text *)contact.c_str(), contact.size(),
                             (ub4)minConnections, (ub4)maxConnections, (ub4)incConnections,
                             (text *)username.c_str(), username.size(),
                             (text *)password.c_str(), password.size(),
                             OCI_SPC_HOMOGENEOUS);
  if(res  != OCI_SUCCESS)
  {
    // should free env, err and pool
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException(std::string("OCISessionPoolCreate ") +msg, code);
  }

  // set a timeout for idle session in the pool
  int limit = 600;
  OCIAttrSet((dvoid *)pool, (ub4)OCI_HTYPE_SPOOL,
             (dvoid *)&limit, (ub4)0,
             (ub4)OCI_ATTR_SPOOL_TIMEOUT,
             error);
}

void SessionFactory::Destroy()
{
  pthread_mutex_lock(&table_access);
      
  sword res;

  // go through the connection table and delete all  
  for (std::map<int, datum>::iterator i = connections.begin(); i != connections.end(); i++)
  {
    // release the connection
    res = OCISessionRelease(i->second.svc,
                            error,
                            NULL,
                            0,
                            OCI_DEFAULT);
      
    if (res != OCI_SUCCESS)
    {
      std::string msg;
      int code = getErrorDetails(res, msg);
      pthread_mutex_unlock(&table_access);
      throw MyException(msg, code);
    }
  
    // erase the connection from the table  
    connections.erase(i);
  }

  pthread_mutex_unlock(&table_access);
      
  // delete the pool
  res = OCISessionPoolDestroy(pool,
                              error, 
                              OCI_DEFAULT);
  if (res != OCI_SUCCESS)
  {
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException(msg + "A", code);
  }
    
  res = OCIHandleFree((dvoid *)pool, OCI_HTYPE_SPOOL);
  if (res != OCI_SUCCESS)
  {
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException(msg + "B", code);
  }
    
  // delete the error handle
  res = OCIHandleFree((dvoid *)error, OCI_HTYPE_ERROR);
  if (res != OCI_SUCCESS)
  {
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException(msg + "C", code);
  }
  
  // delete environment
  res = OCIHandleFree((dvoid *)environment, OCI_HTYPE_ENV);
  if (res != OCI_SUCCESS)
  {
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException(msg + "D", code);
  }

  environment = (OCIEnv *)0;
  error = (OCIError *)0;
  pool = (OCISPool *)0;
  pool_name = 0;
  pool_name_len = 0;
}

SessionFactory::~SessionFactory()
{
  try {
    Destroy();
  }
  catch (...) {
  }
}

int SessionFactory::CreateSession()
{
  sword res;
    
  // create the session

  // prepare authorization handle

  OCIAuthInfo * authp = (OCIAuthInfo *)0;
    
  res = OCIHandleAlloc((dvoid *)environment, 
                       (dvoid **)&authp, (ub4) OCI_HTYPE_SESSION,
                       (size_t) 0, (dvoid **) 0);

  if (res != OCI_SUCCESS)
  {
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException("CreateSession: OCIHandleAlloc: " +msg, code);
  }
  
  res = OCIAttrSet((dvoid *)authp, (ub4)OCI_HTYPE_SESSION,
                   (dvoid *)username.c_str(), (ub4)username.size(),
                   (ub4) OCI_ATTR_USERNAME, 
                   error);
  
  if (res != OCI_SUCCESS)
  {
    // free authorization handle
    OCIHandleFree((dvoid *)authp, 
                  OCI_HTYPE_SESSION);
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException("CreateSession: OCIAttrSet: " +msg, code);
  }

  res = OCIAttrSet((dvoid *)authp, (ub4)OCI_HTYPE_SESSION,
                   (dvoid *)password.c_str(), (ub4)password.size(),
                   (ub4) OCI_ATTR_PASSWORD, 
                   error);

  if (res != OCI_SUCCESS)
  {
    // free authorization handle
    OCIHandleFree((dvoid *)authp, 
                  OCI_HTYPE_SESSION);
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException("CreateSession: OCIAttrSet (2): " +msg, code);
  }


  // get session
    
  OCISvcCtx * service = (OCISvcCtx *)0;
  res = OCISessionGet(environment,
                      error,
                      &service,
                      authp,
                      (OraText *)pool_name, pool_name_len,
                      NULL, 0, NULL, NULL, NULL,
                      OCI_SESSGET_SPOOL | OCI_SESSGET_STMTCACHE);

  if (res != OCI_SUCCESS)
  {
    // free authorization handle
    OCIHandleFree((dvoid *)authp, 
                  OCI_HTYPE_SESSION);
    std::string msg;
    int code = getErrorDetails(res, msg);
    throw MyException("CreateSession: OCISessionGet: " +msg, code);
  }
    
  // free authorization handle
  OCIHandleFree((dvoid *)authp,
                OCI_HTYPE_SESSION);
  
  // register the newly created session

  pthread_mutex_lock(&table_access);
    
  // put connection in table
  struct datum d;
  d.svc = service;
  d.currtime = time(NULL);
    
  ++currentpos;
  if (!currentpos)
    ++currentpos;
    
  connections[currentpos] = d;
   
  int ret = currentpos;
    
  pthread_mutex_unlock(&table_access);
    
  return ret;
}

void SessionFactory::DestroySession(int session)
{
  sword res;
    
  pthread_mutex_lock(&table_access);
    
  // release the connection
  res = OCISessionRelease(connections[session].svc,
                          error,
                          NULL,
                          0,
                          OCI_DEFAULT);

  if (res != OCI_SUCCESS)
  {
    std::string msg;
    int code = getErrorDetails(res, msg);
    pthread_mutex_unlock(&table_access);
    throw MyException(msg + "E", code);
  }
    
  // erase the connection from the table
  connections.erase(connections.find(session));
    
  // release lock
  pthread_mutex_unlock(&table_access);
}

void SessionFactory::Clean()
{
  // go through the connection table and delete those unused for 5 minutes

  pthread_mutex_lock(&table_access);

  time_t current = time(NULL);
    
  for (std::map<int, datum>::iterator i = connections.begin(); i != connections.end(); i++)
  {
    if ((current-(i->second.currtime)) > 300)
    {
      // release the connection
      OCISessionRelease(i->second.svc,
                        error,
                        NULL,
                        0,
                        OCI_DEFAULT);
        
      // erase the connection from the table
      connections.erase(i);
    }
  }
    
  pthread_mutex_unlock(&table_access);
}

Session SessionFactory::GetSession(int session)
{
  // retrieve connection from the table
  OCISvcCtx * svc = connections[session].svc;

  // reset timeout for the connection
  pthread_mutex_lock(&table_access);
  connections[session].currtime = time(NULL);
  pthread_mutex_unlock(&table_access);

  return Session(svc, error, dbVersion, insecure, environment);
}

void SessionFactory::changeSessionId(int oldId, int newId)
{
  pthread_mutex_lock(&table_access);

  struct datum d;
  d.svc = connections[oldId].svc;
  d.currtime = connections[oldId].currtime;

  connections[newId] = d;
  connections.erase(oldId);
  
  pthread_mutex_unlock(&table_access);
}

int SessionFactory::getErrorDetails(sword res,
                             std::string &msg)
{
  sb4 code;
  text buffer[512];
    
  switch (res)
  {
  case OCI_NO_DATA:
    msg = "OCI_NO_DATA";
    return 0;
    break;
  
  case OCI_ERROR:
    OCIErrorGet(error, 1, 0, &code, buffer, 512, OCI_HTYPE_ERROR);
    msg = std::string("AA " ) + reinterpret_cast<char*>(buffer);
    return static_cast<int>(code);
    break;
  
  case OCI_INVALID_HANDLE:
    msg = "OCI_INVALID_HANDLE";
    return 0;
    break;
  
  default:
    msg = "Unknown error code";
    return 0;
  }
}
