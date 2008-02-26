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

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

extern int errno;
}

#include <vector>
#include <iostream>
#include <string>

#include "oraclewrap.h"


static bool donesetup = false;

static std::string port;

static std::string dbcombine(const char * dbname, const char * hostname)
{
  return std::string(dbname) + (std::string(hostname) != "localhost" ? '.' + std::string("hostname") : "");
}

namespace bsq {

bool orinterface::isConnected()
{
  return connected;
}

bool orinterface::setOption(int option, void *value)
{
  if (handle.empty()) {
    setError(ERR_NO_SESSION, "Session must be established before attempting operations");
    return false;
  }
  int counter = 0;
  bool error = false;

  if (!isConnected())
    return false;

  std::string message;
  char number[11];

  sprintf(number, "%09d", option);

  switch(option) {
  case OPTION_SET_SOCKET:
  case OPTION_SET_PORT:
    return true;
    break;
  case OPTION_SET_INSECURE:
    message += std::string(number);
    insecure = value;
    sprintf(number, "%09d", *((bool*)value) ? "1" : "0");
    message += std::string(number);
    break;
  default:
    return true;
    break;
  }
  // If execution arrives here, a request has been formatted.

  int sock = setup_connection();
  if (sock == -1)
    return false;
  message = std::string("O") + handle + message;

  if (!write_wrap(sock, message)) {
    ::close(sock);
    return false;
  }
  std::string msg;
  bool read_success = read_wrap(sock, msg);
  ::close(sock);

  if (read_success) {
    if (isdigit((msg.data()[0]))) {
      char code[6];
      code[0] = (msg.data())[0];
      code[1] = (msg.data())[1];
      code[2] = (msg.data())[2];
      code[3] = (msg.data())[3];
      code[4] = (msg.data())[4];
      code[5] = '\0';
      err = atoi(code);
      std::string s = std::string(msg, 5);
      setError(ERR_DBERR, "middleman cannot fetch result : " +s);
      return false;
    }
  }
  else {
    /* Error message already set by read_wrap() */
    return false;
  }
  if (msg.size() < 2) {
    setError(ERR_DBERR, "Unknown error from middleman");
    return false;
  }

  /* no Error */
  return true; 
}

char *orinterface::errorMessage()
{
  return (char*)errorString.c_str();
}

bool orinterface::read_wrap(int sock, std::string& msg)
{
  int size;
  if (read(sock, &size, sizeof(size)) != sizeof(size)) {
    setError(ERR_NO_DB, "Cannot read data from middleman : " + std::string(strerror(errno)));
    return false;
  }

  char * buffer = (char *)malloc(size);
  if (read(sock, buffer, size) != size) {
    free(buffer);
    setError(ERR_NO_DB, "Cannot read data from middleman : " + std::string(strerror(errno)));
    return false;
  }

  msg = std::string(buffer, size);
  free(buffer);
  return true;
}

bool orinterface::write_wrap(int sock, const std::string& msg)
{
  int size = msg.size();
  if (write(sock, &size, sizeof(size)) == -1) {
    setError("Cannot write data to middleman : " + std::string(strerror(errno)));
    return false;
  }

  if (write(sock, msg.data(), size) == -1) {
    setError("Cannot write data to middleman : " + std::string(strerror(errno)));
    return false;
  }
  return true;
}

int orinterface::setup_connection()
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if(sock == -1) {
    setError("Cannot connect to middleman : " + std::string(strerror(errno)));
    return -1;
  }
  
  struct sockaddr_in peeraddr_in;

  memset((char *)&peeraddr_in, 0, sizeof(peeraddr_in));
  peeraddr_in.sin_family = AF_INET;
  peeraddr_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  peeraddr_in.sin_port=htons(atoi(port.c_str()));
  
  if (0 == ::connect(sock, 
                     (struct sockaddr*)&peeraddr_in,
                     sizeof(peeraddr_in))) {
    return sock;
  }
  else {
    ::close(sock);
    setError("Cannot connect to middleman : " + std::string(strerror(errno)));
    return -1;
  }
}

void orinterface::setError(const std::string &message)
{
  err = ERR_DBERR;
  errorString = message;
}

void orinterface::setError(int err, const std::string &message)
{
  this->err = err;
  errorString = message;
}

bool orinterface::initialize_conn(const char *dbname,
                                  const char *hostname,
                                  const char *user,
                                  const char *password)
{
  int sock = -1;

  if (!donesetup) {
    donesetup = true;

    /* create the socket that will be used by middleman */

    struct sockaddr_in myaddr_in;
    memset((char *)&myaddr_in, 0, sizeof(myaddr_in));
    myaddr_in.sin_family = AF_INET;
    myaddr_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    myaddr_in.sin_port = htons(0);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
      setError("Cannot start middleman : " + std::string(strerror(errno)));
      return false;
    }
    
    unsigned int value = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&value, sizeof(socklen_t));
  
    int result = bind(sock, (struct sockaddr *)&myaddr_in, sizeof(struct sockaddr_in));
    if (result == -1) {
      setError("Cannot start middleman : " + std::string(strerror(errno)));
      goto err;
    }

    int size = sizeof(myaddr_in);
    memset((char *)&myaddr_in, 0, sizeof(myaddr_in));
    if (getsockname(sock, (sockaddr*)(&myaddr_in), (socklen_t*)(&size)) == -1) {
      setError("Cannot start middleman : " + std::string(strerror(errno)));
      goto err;
    }

    unsigned int portnum = ntohs(myaddr_in.sin_port);
    char buffer[100];
    sprintf(buffer, "%u", portnum);
    port = std::string(buffer);

    sprintf(buffer, "%u", sock);
    std::string socknum = std::string(buffer);


    /* forks */
    pid_t pid = fork();
    middlemanpid = pid;
    /* child runs middleman */
    if (!pid) {
      std::string procname = "middleman" + std::string(dbname);
      int val = execlp("middleman", procname.c_str(), buffer, 
                       dbcombine(dbname, hostname).c_str(), user, NULL);
      setError("Cannot run middleman : " + std::string(strerror(errno)));
      goto err;
    }
    /* father wait the middleman to be up then send the password and listen for
       an eventual error message */
    else {
      ::close(sock);
      sock = -1;
      sleep(5);
      
      sock = setup_connection();
      
      if (sock == -1)
        return false;

      send(sock, password, strlen(password), 0);
      std::string msg;
      bool read_success = read_wrap(sock, msg);
      ::close(sock);
      sock = -1;

      if (!read_success)
        goto err;

      if (msg != "A") {
        std::string s = std::string(msg, 5);
        setError("Cannot start middleman : " + s);
        goto err;
      }
      return true;
    }
  }
  return true;

 err:
  if (sock != -1)
    ::close(sock);
  return false;

}

std::string orinterface::make_conn(const char *dbname,
                                   const char *hostname,
                                   const char *user,
                                   const char *password,
                                   int *err)
{
  int sock = setup_connection();

  if (sock == -1)
    return "";

  if (!write_wrap(sock, "C")) {
    ::close(sock);
    return "";
  }
  std::string msg;
  bool read_success = read_wrap(sock, msg);
  ::close(sock);

  if (!read_success)
    return "";

  if((msg.data())[0] != 'H') { 
    char code[6];
    code[0] = (msg.data())[0];
    code[1] = (msg.data())[1];
    code[2] = (msg.data())[2];
    code[3] = (msg.data())[3];
    code[4] = (msg.data())[4];
    code[5] = '\0';
    *err = atoi(code);
    std::string s = std::string(msg, 5);
    setError("middleman cannot make connection : " + s);
    return "";
  }

  std::string value = std::string(msg, 1);
  return value;
}

orinterface::orinterface() : err(0), handle(""), dbVersion(-1), errorString(""),
                             dbname(NULL), hostname(NULL), user(NULL),
                             password(NULL), connected(false), insecure(false),
                             middlemanpid(-1)
{}

int orinterface::error(void) const
{
  return err; 
}

bool orinterface::connect(const char *dbname, 
                          const char *hostname, 
                          const char *user, 
                          const char *password)
{

  if (!donesetup) {
    this->dbname = strdup(dbname);
    this->hostname = strdup(hostname);
    this->user = strdup(user);
    this->password = password;

    if (!this->dbname || !this->hostname || !this->user) {
      free(this->dbname);
      free(this->hostname);
      free(this->user);
      setError("No memory!");
      return false;
    }

    return (connected = initialize_conn(dbname, hostname, user, password));
  }
  return true;
}

sqliface::interface *orinterface::getSession()
{
  orinterface *o = new orinterface();
  o->dbname = dbname;
  o->hostname = hostname;
  o->user = user;
  o->password = password;
  o->connected = connected;

  o->handle = o->make_conn(o->dbname, o->hostname, o->user, 
                           o->password, &(o->err));

  if (o->handle.empty()) {
    delete o;
    return NULL;
  }
  return o;
}

void orinterface::releaseSession(interface *o)
{
  o->close();
  delete o;
}

bool orinterface::reconnect()
{
  close();
  if (!donesetup)
    if (initialize_conn(dbname, hostname, user, password)) {
      handle = make_conn(dbname, hostname, user, password, &err);
      if (handle.empty())
        return false;
      return true;
    }

  return false;
}

void orinterface::close() 
{
  if (!handle.empty()) {
    int sock = setup_connection();
    if (sock != -1)
      write_wrap(sock, std::string("D") + handle);
    ::close(sock);
    if (middlemanpid != -1)
      kill(middlemanpid, 9);
    middlemanpid = -1;
  }
  donesetup = false;
}

orinterface::~orinterface()
{
  close();
}

bool orinterface::operation(int operation_type, void *result, ...)
{
  if (handle.empty()) {
    setError(ERR_NO_SESSION, "Session must be established before attempting operations");
    return false;
  }

  va_list va;
  va_start(va, result);

  int counter = 0;
  bool error = false;

  if (!result || !isConnected())
    return false;

  std::vector<std::string> *fqans = ((std::vector<std::string> *)result);
  std::vector<gattrib> *attrs = ((std::vector<gattrib> *)result);
  signed long int uid = -1;
  char *group = NULL;
  char *role = NULL;
  X509 *cert = NULL;

  /* Builds message */
  std::string message;

  char number[11];

  /* Encode operation_type */
  sprintf(number, "%03d\0", operation_type);
  message += std::string(number);

  switch (operation_type) {
  case OPERATION_GET_GROUPS_AND_ROLE:
  case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
    uid = va_arg(va, signed long int);
    group = va_arg(va, char *);
    role = va_arg(va, char *);
    if (uid == -1 || !group || !role)
      error = true;
    else {
      sprintf(number, "%09d", uid);
      message += std::string(number);
      sprintf(number, "%09d", strlen(group));
      message += std::string(number) + group;
      sprintf(number, "%09d", strlen(role));
      message += std::string(number) + role;
    }
    break;

  case OPERATION_GET_ROLE:
  case OPERATION_GET_ROLE_ATTRIBS:
    uid = va_arg(va, signed long int);
    role = va_arg(va, char *);
    if (uid == -1 || !role)
      error = true;
    else {
      sprintf(number, "%09d", uid);
      message += std::string(number);
      sprintf(number, "%09d", strlen(role));
      message += std::string(number) + role;
    }
    break;

  case OPERATION_GET_GROUPS:
  case OPERATION_GET_ALL:
  case OPERATION_GET_GROUPS_ATTRIBS:
  case OPERATION_GET_ALL_ATTRIBS:
    uid = va_arg(va, signed long int);
    if (uid == -1)
      error = true;
    else {
      sprintf(number, "%09d", uid);
      message += std::string(number);
    }
    break;

  case OPERATION_GET_VERSION:
    break;

  case OPERATION_GET_USER:
    cert = va_arg(va, X509 *);
    if (!cert)
      error = true;
    else {
      int size = i2d_X509(cert, NULL);
      unsigned char *buffer = (unsigned char *)malloc(size);
      unsigned char *savebuffer = buffer;
      if (!buffer)
        error = true;
      else {
        (void)i2d_X509(cert, &buffer);
        sprintf(number, "%09d", size);
        message += std::string(number) + std::string((const char *)savebuffer, size);
        free(savebuffer);
      }
    }
    break;

  default:
    error = true;
  }

  if (error) {
    setError(ERR_NO_PARAM, "Error in parsing arguments!");
    return false;
  }
    
  int sock = setup_connection();
  if (sock == -1)
    return false;

  std::string sendmsg = std::string("Q") + handle + message;

  if (!write_wrap(sock, sendmsg)) {
    ::close(sock);
    return false;
  }
  std::string msg;
  bool read_success = read_wrap(sock, msg);
  ::close(sock);

  if (!read_success)
    return false;

  if (isdigit((msg.data()[0]))) {
    char code[6];
    code[0] = (msg.data())[0];
    code[1] = (msg.data())[1];
    code[2] = (msg.data())[2];
    code[3] = (msg.data())[3];
    code[4] = (msg.data())[4];
    code[5] = '\0';
    err = atoi(code);
    std::string s = std::string(msg, 5);
    setError(ERR_DBERR, "middleman cannot fetch result : " +s);
    return false;
  }

  if (msg.size() < 2) {
    setError(ERR_DBERR, "Unknown error from middleman");
    return false;
  }

  std::string::size_type pos1 = std::string::npos;
  std::string::size_type pos2 = std::string::npos;
  std::string::size_type pos3 = std::string::npos;

  msg =msg.substr(1);

  /* Parse answer: */
  switch (operation_type) {
  case OPERATION_GET_VERSION:
    /* answer is an integer */
    *((int*)result) = atoi(msg.c_str());
    break;
  case OPERATION_GET_USER:
    /* answer is a signed long int */
    *((signed long int *)result) = atoi(msg.c_str());
    break;

  case OPERATION_GET_ROLE:
  case OPERATION_GET_GROUPS:
  case OPERATION_GET_ALL:
  case OPERATION_GET_GROUPS_AND_ROLE:
    /* answer is a sequence of FQANs */
    pos1 = msg.find('\1');
    while (pos1 != std::string::npos) {
      fqans->push_back(msg.substr(0, pos1));
      msg = msg.substr(pos1+1);
      pos1 = msg.find('\1');
    }
    break;

  case OPERATION_GET_ROLE_ATTRIBS:
  case OPERATION_GET_GROUPS_ATTRIBS:
  case OPERATION_GET_ALL_ATTRIBS:
  case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
    /* answer is a sequence of Attributes */
    pos1 = msg.find('\1');
    pos2 = msg.find('\1', pos1+1);
    pos3 = msg.find('\1', pos2+1);
    while (pos1 != std::string::npos && pos2 != std::string::npos &&
           pos3 != std::string::npos) {
      gattrib ga;
      ga.name  = msg.substr(0, pos1);
      ga.value = msg.substr(pos1+1, pos2-pos1-1);
      ga.qualifier  = msg.substr(pos2+1, pos3-pos2-1);
      attrs->push_back(ga);
      msg = msg.substr(pos3+1);
      pos1 = msg.find('\1');
      pos2 = msg.find('\1', pos1+1);
      pos3 = msg.find('\1', pos2+1);
    }
    break;
  }
  return true;
}

} // namespace bsq

extern "C" {
sqliface::interface *CreateDB()
{
  return new bsq::orinterface();
}

int getDBInterfaceVersion()
{
  return 3;
}

int getDBInterfaceVersionMinor()
{
  return 1;
}
}
