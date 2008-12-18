/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - valerio.venturi@cnaf.infn.it
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

#include "config.h"
#include "ociwrap.hpp"
#include "dbwrap.h"

extern "C"
{
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <openssl/x509.h>
}

#include <vector>
#include <string>
#include <map>

#define INTSIZE (((sizeof(int)*CHAR_BIT)/3)+2)
#define HANDLESIZE (INTSIZE - 1)

static int delay = 0;

static int         port = 0;
static std::string contact;
static std::string username;
static std::string password;

int minConnections;
int maxConnections;
int incConnections;

static SessionFactory factory;

static pthread_t tid, tid2;
static int value = 0;
static int dummy = 1;

static void *execute(void *sockp);
static void *connection_garbage(void *null);

static void do_query(int sock, const std::string& handle, const std::string& query);
static void do_options(int sock, const std::string query);
static void do_send(int sock, const std::string &rows);
static int decode(const std::string& s);
static std::string encode(int i);

#ifndef HAVE_SIGACTION
static void sig_handler()
{
  exit(0);
}
#else
static void sig_handler(int sig)
{
  exit(0);
}
#endif

int main(int argc, char *argv[])
{
#ifdef HAVE_SIGACTION
  struct sigaction action;
  action.sa_handler = sig_handler;
  action.sa_flags = 0;
  sigemptyset(&(action.sa_mask)); 	/* ignore all known signals */
  sigaction(SIGTERM,&action,NULL);  /* ensures that SA_RESTART is NOT set */
#else
  signal(SIGTERM, sig_handler); 
#endif

  // check argument
  if (argc != 4)
    exit(9);
  
  int sock = atoi(argv[1]);
  contact = std::string(argv[2]);
  username = std::string(argv[3]);

  char * tmp;
  tmp = getenv("VOMSORACLE_MIN_CONNECTION");
  minConnections = (tmp ? atoi(tmp) : 2);
  tmp = getenv("VOMSORACLE_MAX_CONNECTION");
  maxConnections = (tmp ? atoi(tmp) : 10);
  tmp = getenv("VOMSORACLE_INC_CONNECTION");
  incConnections = (tmp ? atoi(tmp) : 1);
  tmp = getenv("VOMSORACLE_DELAY_CONNECTION");
  delay = (tmp ? atoi(tmp) : 2);

  if (sock == 0)
    exit(10);
  
  // listen on the given socket
  listen(sock, 100);

  // accept connections
  int newsock;
  struct sockaddr_in peeraddr_in;
  socklen_t addrlen = sizeof(peeraddr_in);

#ifndef HAVE_SOCKLEN_T
  int addrlenint = (int)addrlen;
  newsock = accept(sock, (struct sockaddr*)(&peeraddr_in), &((int)addrlen));
#else
  newsock = accept(sock, (struct sockaddr*)(&peeraddr_in), &addrlen);
#endif
  
  // receive the password
  char buffer[100];
  ssize_t size;
  size = recv(newsock, buffer, 99, 0);
    
  if (buffer[size-1] == '\n')
    size --;
  if (buffer[size-1] == '\r')
    size --;
  
  buffer[size]='\0';
  password = std::string(buffer);

  try {
    // initialize session factory
    factory.init(contact, 
                 username,
                 password,
                 minConnections,
                 maxConnections,
                 incConnections);
  }
  catch(std::exception& e) {
    char * tmp = (char *)e.what();
    do_send(newsock, std::string(tmp));
    exit(1);
  }

  // tell voms all was ok
  do_send(newsock, "A");
  close(newsock);

  // start the garbage thread
  pthread_create(&tid2, NULL, connection_garbage, NULL);
  
  // wait for connections
  for (;;) {
    int *newsockp = new int;
#ifndef HAVE_SOCKLEN_T
    *newsockp = accept(sock, (struct sockaddr*)&peeraddr_in, &((int)addrlen));
#else
    *newsockp = accept(sock, (struct sockaddr*)&peeraddr_in, &addrlen);
#endif
    pthread_create(&tid, NULL, execute, newsockp);
  }
}

static void * execute(void *sockp)
{
  pthread_detach(pthread_self());

  int sock = *((int *)sockp);
  delete ((int *)sockp);

  // read voms command 
  int size;
  if (read(sock, &size, sizeof(size)) == -1) {
    perror("middleman:");
    exit(99);
  }
  
  // interpret command
  char * text = (char *)malloc(size + 1);
  if (text) {
    read(sock, text, size);
    text[size] = '\0';
      
    std::string textmsg = std::string(text, size);
    std::string handle = textmsg.substr(1, HANDLESIZE);

    int session;
    std::string id;
    
    try {
      switch(text[0]) 
      {
      case 'C':
        id = encode(factory.CreateSession());
        do_send(sock, "H" +id);
        break;
        
      case 'Q':
        do_query(sock, handle, textmsg.substr(1 + HANDLESIZE));
        break;

      case 'O':
        do_options(sock, textmsg.substr(1 + HANDLESIZE)); 
        break;

      case 'D':
        session = decode(handle);
        factory.DestroySession(session);
        break;
      }
    }
    catch(std::exception& e) {
      char *tmp = (char *)e.what();
      do_send(sock, std::string(tmp));
      free(tmp);
    }
    
    free(text);
  }

  // close the socket and exit
  close(sock);
  pthread_exit(&value);
}

static void do_options(int sock, const std::string query)
{
  std::string real = query;

  int optionname = atoi(real.substr(0, 9).c_str());

  real = real.substr(9);

  switch (optionname) {
  case OPTION_SET_INSECURE:
    {
      int optionvalue = atoi(real.substr(0, 9).c_str());

      if (optionvalue)
        factory.insecure = true;
      else
        factory.insecure = false;
    }
    break;
  default:
    break;
  }
  do_send(sock, "HOK");
}

void do_query(int sock, const std::string& handle, const std::string& query)
{
  // drop white spaces at the beginnning
//   const char * str = query.c_str();
//   while (isspace(*str))
//     str++;
//   std::string real = std::string(str);

  std::string real = query;

  Session session = factory.GetSession(decode(handle));
  
  // execute select or non-select statement
  std::vector<std::string> results;
  
  int operation = atoi(query.substr(0,3).c_str());

  real = real.substr(3);

  switch (operation) {
  case OPERATION_GET_USER: 
    {
      int size = atoi(real.substr(0,9).c_str());
      std::string buffer = real.substr(9);
      signed long int uid = -1;
      unsigned char *realbuf = (unsigned char *)buffer.c_str();
      X509 *cert = d2i_X509(NULL, &realbuf, size);
      bool result = session.operationGetUID(cert, &uid);
      X509_free(cert);
      if (result) {
        char strbuffer[20];
        snprintf(strbuffer, 20, "%ld\0", uid);
        do_send(sock, "H"+std::string(strbuffer));
      }
      else
        do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_VERSION:
    {
      if (factory.dbVersion == -1) {
        int ver;
        bool result = session.operationGetDBVersion(&ver);
        if (result)
          session.dbVersion = factory.dbVersion = ver;
        else {
          do_send(sock, session.getError());
          return;
        }
      }
      char buffer[20];
      snprintf(buffer, 20, "%ld", factory.dbVersion);
      
      do_send(sock, "H"+std::string(buffer));
      return;
    }
    break;
    
  case OPERATION_GET_ALL:
    {
      signed long int uid = atoi(real.substr(0,9).c_str());
      std::vector<std::string> fqans;

      if (session.operationGetAll(uid, fqans)) {
        std::string result = "";
        for (std::vector<std::string>::iterator i = fqans.begin();
             i != fqans.end(); i++)
          result += *i + "\1";
        do_send(sock, "H"+result);
        return;
      }
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_ALL_ATTRIBS:
    {
      signed long int uid = atoi(real.substr(0,9).c_str());
      std::vector<gattrib> attribs;
      
      if (session.operationGetAllAttribs(uid, attribs)) {
        std::string result = "";
        for (std::vector<gattrib>::iterator i = attribs.begin();
             i != attribs.end(); i++)
          result += i->name + "\1" + i->value + "\1" + i->qualifier + "\1";
        do_send(sock, "H"+result);
        return;
      }
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_GROUPS:
    {
      signed long int uid = atoi(real.substr(0,9).c_str());
      std::vector<std::string> fqans;

      if (session.operationGetGroups(uid, fqans)) {
        std::string result = "";
        for (std::vector<std::string>::iterator i = fqans.begin();
             i != fqans.end(); i++)
          result += *i + "\1";
        do_send(sock, "H"+result);
        return;
      }
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_GROUPS_ATTRIBS:
    {
      signed long int uid = atoi(real.substr(0,9).c_str());
      std::vector<gattrib> attribs;

      if (session.operationGetGroupAttribs(uid, attribs)) {
        std::string result = "";
        for (std::vector<gattrib>::iterator i = attribs.begin();
             i != attribs.end(); i++)
          result += i->name + "\1" + i->value + "\1" + i->qualifier + "\1";
        do_send(sock, "H"+result);
        return;
      }
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_ROLE:
    {
      signed long uid = atoi(real.substr(0,9).c_str());
      const char *role = real.substr(18).c_str();
      std::vector<std::string> fqans;

      if (session.operationGetRoles(uid, fqans, role)) {
        std::string result = "";
        for (std::vector<std::string>::iterator i = fqans.begin();
             i != fqans.end(); i++)
          result += *i + "\1";
        do_send(sock, "H"+result);
        return;
      }
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_ROLE_ATTRIBS:
    {
      signed long int uid = atoi(real.substr(0,9).c_str());
      char *role = strdup(real.substr(18).c_str());
      std::vector<gattrib> attribs;

      if (role && session.operationGetRoleAttribs(uid, role, attribs)) {
        std::string result = "";
        for (std::vector<gattrib>::iterator i = attribs.begin();
             i != attribs.end(); i++)
          result += i->name + "\1" + i->value + "\1" + i->qualifier + "\1";
        do_send(sock, "H"+result);
        return;
      }
      free(role);
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_GROUPS_AND_ROLE:
    {
      signed long uid = atoi(real.substr(0,9).c_str());
      int grouplen = atoi(real.substr(9,9).c_str());
      char *group = strdup(real.substr(18, grouplen).c_str());
      int rolelen = atoi(real.substr(18+grouplen, 9).c_str());
      char *role = strdup(real.substr(18+grouplen+9, rolelen).c_str());
      std::vector<std::string> fqans;

      if (session.operationGetGroupsAndRole(uid, fqans, group, role)) {
        free(group);
        free(role);
        std::string result = "";
        for (std::vector<std::string>::iterator i = fqans.begin();
             i != fqans.end(); i++)
          result += *i + "\1";
        do_send(sock, "H"+result);
        return;
      }
      free(group);
      free(role);
      do_send(sock, session.getError());
    }
    break;

  case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
    {
      signed long int uid = atoi(real.substr(0,9).c_str());
      int grouplen = atoi(real.substr(9,9).c_str());
      char *group = strdup(real.substr(18, grouplen).c_str());
      int rolelen = atoi(real.substr(18+grouplen, 9).c_str());
      char *role = strdup(real.substr(18+grouplen+9, rolelen).c_str());
      std::vector<gattrib> attribs;

      if (!group || !role) {
        free(group);
        free(role);
        do_send(sock, "000000Out of memory");
        break;
      }
      if (session.operationGetGroupAndRoleAttribs(uid, (char *)group, (char *)role, attribs)) {
        std::string result = "";
        for (std::vector<gattrib>::iterator i = attribs.begin();
             i != attribs.end(); i++)
          result += i->name + "\1" + i->value + "\1" + i->qualifier + "\1";
        do_send(sock, "H"+result);
        free(group);
        free(role);
        return;
      }
      free(group);
      free(role);

      do_send(sock, session.getError());
    }
    break;

  default:
    do_send(sock, "000000");
    break;
  }
  return;
}

static void *connection_garbage(void *null)
{
  pthread_detach(pthread_self());
  
  // sleep 5 minutes then clean old session
  for (;;) {
    for (int i = 0; i < 300; i++) {
      sleep(1);
    }
    factory.Clean();
  }
}

static void do_send(int sock, const std::string &result)
{
  int size;
  size = result.size();
  write(sock, &size, sizeof(size));
  write(sock, result.data(), size);
}

static std::string encode(int i)
{
  char val[INTSIZE];
  memset(val, 0, INTSIZE);
  
  sprintf(val, "%0*2$d\0", i, HANDLESIZE);
  
  return std::string(val, HANDLESIZE);
}

static int decode(const std::string& s)
{
  return atoi(s.c_str());
}
