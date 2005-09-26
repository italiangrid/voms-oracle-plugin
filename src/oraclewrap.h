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

#include "dbwrap.h"
#include <occi.h>

namespace bsq {

class orinterface;
class orquery;

class orresults : public sqliface::results 
{

 public:

  friend class orquery;
  ~orresults();
  const std::string get(int) const;
  const std::string get(const std::string&) const;
  bool valid() const;
  bool next();
  const std::string name(int) const;
  int size() const;

 private:

  orresults();
  orresults(const orresults &);
  orresults(oracle::occi::ResultSet *, 
	    oracle::occi::Statement *,
	    oracle::occi::Connection *);
  
  oracle::occi::Connection * conn;
  oracle::occi::Statement * stmt;
  oracle::occi::ResultSet * r;
  bool value;
};


class orquery : public sqliface::query 
{

 public:

  friend class oriterator;
  friend class orinterface;
  orquery(const orquery &);
  ~orquery();

  sqliface::query &operator<<(std::string);

  sqliface::results* result(void);

  void exec(void);
  int  error(void) const;

private:

  orquery();
  orquery(orinterface&);

  std::string query;
  oracle::occi::Connection * conn;
  oracle::occi::Statement * stmt;
  int err;
};

class orinterface : public sqliface::interface 
{
  friend class orquery;
 
 public:
  
  orinterface();
  orinterface(const char *, const char *, const char *, const char *);
  ~orinterface(void);
  
  int error(void) const;
  void connect(const char *, const char *, const char *, const char *);
  sqliface::query *newquery();
 
 private:
  
  orinterface(const orinterface &);
  std::string dbcombine(const char *, const char *);
  oracle::occi::Environment *env;
  oracle::occi::Connection *conn;
  int err;

};

} // namespace bsq
