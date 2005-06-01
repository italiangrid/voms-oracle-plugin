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

#include <vector>
#include <iostream>

#include "oraclewrap.h"

#define CATCH \
catch(oracle::occi::SQLException& e) \
{ \
  throw sqliface::DBEXC(e.getMessage()); \
} \
catch (...) \
{ \
  throw sqliface::DBEXC(); \
} \

namespace bsq {

orinterface::orinterface(const char *dbname,
			 const char *hostname,
			 const char *user,
			 const char *password) : err(0)
{
  try 
  {
    env = oracle::occi::Environment::createEnvironment();
    if (env)
      conn = env->createConnection(std::string(user), 
				   std::string(password),
				   dbcombine(dbname, hostname));
  }
  CATCH
}

orinterface::orinterface() : env(NULL), 
			     conn(NULL), 
			     err(0) {}

int orinterface::error(void) const
{
  return err; 
}

void orinterface::connect(const char *dbname, 
			  const char *hostname, 
			  const char *user, 
			  const char *password)
{
  try 
  {
    env = oracle::occi::Environment::createEnvironment();
    if (env)
      conn = env->createConnection(std::string(user), 
				   std::string(password),
				   dbcombine(dbname, hostname));
  }
  CATCH
}

std::string orinterface::dbcombine(const char * dbname, 
				   const char * hostname)
{
  return std::string(dbname) + (std::string(hostname) != "localhost" ? '.' + std::string("hostname") : "");
}

orinterface::~orinterface()
{
  if(conn)
    env->terminateConnection(conn);
  if(env)
    oracle::occi::Environment::terminateEnvironment(env);
}

sqliface::query *orinterface::newquery()
{
  return new orquery(*this);
}

orquery::orquery(bsq::orinterface &face) : conn(face.conn), 
					   stmt(NULL), 
					   query("") {}

orquery::~orquery(void) 
{
  try 
  {
    if (stmt)
      conn->terminateStatement(stmt);
  }
  CATCH
}

sqliface::query &orquery::operator<<(std::string s)
{
  std::string tmp = query + s;
  
  int         pos = tmp.find_last_of('\n');
  if (pos == -1)
    pos = 0;

  query = tmp.substr(pos, tmp.size() - pos);
  return *this;
}

void orquery::exec(void)
{
  try 
  {
    if(stmt)
      conn->terminateStatement(stmt);
    stmt = NULL;
  }
  CATCH

  try 
  {
    stmt = conn->createStatement(query);
    (void)stmt->executeUpdate();
  }
  CATCH

  query = "";
}

int orquery::error(void) const
{
  return 0;
}

sqliface::results* orquery::result(void)
{
  if(stmt)
    conn->terminateStatement(stmt);

  oracle::occi::ResultSet *res;

  try 
  {
    stmt = conn->createStatement(query);
    res = stmt->executeQuery();
  }
  CATCH

  if (res) 
  {
    bsq::orresults * o = new bsq::orresults(res, stmt, conn);
    if (o)
      stmt = NULL;
    return o;
  }
  else
    return NULL;
}

orresults::orresults(oracle::occi::ResultSet *res,
		     oracle::occi::Statement *s,
		     oracle::occi::Connection *c) : conn(c),
						    stmt(s), 
						    r(res), 
						    value(true) 
{
  try 
  {
    if (r->next() == oracle::occi::ResultSet::END_OF_FETCH)
      value = false;
  }
  CATCH
}

bool orresults::next() 
{
  try 
  {
    if (r->next() == oracle::occi::ResultSet::END_OF_FETCH)
      value = false;
    return value;
  }
  CATCH
}

const std::string orresults::get(int i) const 
{
  try 
  {
    return r->getString(i);
  }
  CATCH
}

const std::string orresults::get(const std::string& s) const
{
  try
  {
    int current = 1;
    int index = -1;

    std::vector<oracle::occi::MetaData> md = r->getColumnListMetaData();
    for(std::vector<oracle::occi::MetaData>::iterator i = md.begin(); i != md.end(); ++i, ++current) 
    {
      if (i->getString(oracle::occi::MetaData::ATTR_NAME) == s)
      {
	index = current;
	break;
      }
    }
    if (index != -1)
      return r->getString(index);
    else
      throw sqliface::DBEXC("column '" + s + "' not found!");
  }
  CATCH
}

const std::string orresults::name(int i) const
{
  try 
  {
    std::vector<oracle::occi::MetaData> md = r->getColumnListMetaData();
    return md[i].getString(oracle::occi::MetaData::ATTR_NAME);
  }
  CATCH
}

orresults::~orresults() 
{
  try 
  {
    if(r)
      stmt->closeResultSet(r);

    if(stmt)
      conn->terminateStatement(stmt);
    stmt = NULL;
    
  } 
  CATCH
}

int orresults::size() const
{
  try 
  {
    std::vector<oracle::occi::MetaData> md = r->getColumnListMetaData();
    std::vector<oracle::occi::MetaData>::iterator cur = md.begin(),
                                                  end = md.end();
    int i = 0;

    while (cur != end) 
    {
      i++;
      cur++;
    }
    return i;
  }
  CATCH
}

bool orresults::valid() const
{
  return value;
}
     
}

extern "C" {
sqliface::interface *CreateDB()
{
  return new bsq::orinterface();
}

}
