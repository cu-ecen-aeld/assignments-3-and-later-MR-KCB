#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_OUTPUT_STR        (1024U)
#define OUT_DIRECTORY         ("/var/tmp/aesdsocketdata")

#define SET_SIG_FLAG(x)     (1U << x)
#define GET_SIG_FLAG(x)     (x)
#define NO_CAUTH_SIGNAL     (0U)


typedef enum 
{
  eCautghSigInt,
  eCautghSigTerm
} tcaugthSign;

tcaugthSign caugthSig = 0;

static void sigActionHdlr();
static void signal_handler( int signal_number);
static void genExitError(char * inStr, int outErr);
static bool parseArguments(int argc, char *argv[]);
static void closeFD(int fdSocket, int fdAccept);
static void handleAcceptedConnection(int fileDescriptorSocket, struct addrinfo *serverInfo);
static void handlerData(int fileDescriptorAccept);

char printStr[MAX_OUTPUT_STR];

int main(int argc, char *argv[])
{
  int status;
  int fileDescriptorSocket;
  //struct sockaddr_in serverAddr;
  struct addrinfo hints;
  struct addrinfo *serverInfo;
  int reuseAddr = 1;

  pid_t retForkPid = 0;

  // Init signal handler
  sigActionHdlr();

  openlog("[LOG Program]", LOG_PID | LOG_NDELAY ,LOG_USER);

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  status = getaddrinfo("localhost", "9000", &hints, &serverInfo);
  if (0 != status)
  {
    genExitError("Failed to give node and service from getaddrinfo", status);
  }

  fileDescriptorSocket = socket(serverInfo->ai_family, serverInfo->ai_socktype, serverInfo->ai_protocol);
  if (-1 == fileDescriptorSocket )
  {
    freeaddrinfo(serverInfo); /* Release server info this also free the memory */
    genExitError("Failed to creates an endpoint and return a descriptor from socket", fileDescriptorSocket);

  }
  setsockopt(fileDescriptorSocket, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));

  status = bind(fileDescriptorSocket, serverInfo->ai_addr, serverInfo->ai_addrlen);
  if (-1 == status)
  {
    close(fileDescriptorSocket);
    freeaddrinfo(serverInfo); /* Release server info this also free the memory */
    genExitError("Failed to assign adress specified from bind", status);
  }

  if (true == parseArguments(argc, argv))
  {
    retForkPid = fork();
    if (-1 == retForkPid)
    {
      freeaddrinfo(serverInfo); /* Release server info this also free the memory */
      genExitError("Faild to create a demon", errno);
    }
  }

  status = listen(fileDescriptorSocket, 1);
  if (-1 == status)
  {
    close(fileDescriptorSocket);
    freeaddrinfo(serverInfo); /* Release server info this also free the memory */
    genExitError("Failed to accept incoming connections request from listen", status);
  }

  if (0 == retForkPid)
  {
    handleAcceptedConnection(fileDescriptorSocket, serverInfo);
  }
  
  freeaddrinfo(serverInfo); /* Release server info this also free the memory */
  
  return errno;
}


static void sigActionHdlr()
{
  struct sigaction newAction;

  memset(&newAction, 0, sizeof(struct sigaction));
  newAction.sa_handler = signal_handler;
  if (sigaction(SIGTERM, &newAction, NULL) != 0) 
  {
    printf("Error registering for SIGTERM: Error %d (%s)", errno, strerror(errno));
    exit(errno);
  }
  if (sigaction(SIGINT, &newAction, NULL) != 0) 
  {
    printf("Error registering for SIGINT: Error %d (%s)", errno, strerror(errno));
    exit(errno);
  }

}

static bool parseArguments(int argc, char *argv[])
{
  bool status = false;
  if ((argc > 1) && (0 == strcmp(argv[1], "-d")))
  {
    status = true;
  }
  return status;
}

static void signal_handler( int signal_number)
{
  if (signal_number == SIGINT)
  {
    caugthSig = SET_SIG_FLAG(eCautghSigInt);
  }
  else if (signal_number == SIGTERM)
  {
    caugthSig = SET_SIG_FLAG(eCautghSigTerm);
  }
  else
  {
    // Do nothing
  }
}

static void closeFD(int fdSocket, int fdAccept)
{
  close(fdSocket);
  close(fdAccept);
}

static void genExitError(char * inStr, int outErr)
{
  perror(inStr);
  printf("[Exit] %s\n", inStr);
  syslog(LOG_ERR, "%s",inStr);
  exit(outErr);
}

static void handleAcceptedConnection(int fileDescriptorSocket, struct addrinfo *serverInfo)
{
  int fileDescriptorAccept;
  void *srcAddr;
  socklen_t addrStorageLength = sizeof(struct sockaddr_storage);
  char ipStr[INET_ADDRSTRLEN];
  struct sockaddr_storage addrStorage;

  while (1)
  {
    // Accept connection
    fileDescriptorAccept = accept(fileDescriptorSocket, (struct sockaddr *) &addrStorage, &addrStorageLength);
    
    // Verify no signal to stop was received
    if (NO_CAUTH_SIGNAL != caugthSig)
    {
      srcAddr = &((struct sockaddr_in *)serverInfo->ai_addr)->sin_addr;
      inet_ntop(serverInfo->ai_family, srcAddr, ipStr, sizeof(ipStr));
      remove(OUT_DIRECTORY);
      snprintf(printStr, sizeof(printStr), "Close connection from %s", ipStr);
      freeaddrinfo(serverInfo); /* Release server info this also free the memory */
      genExitError(&printStr[0] , GET_SIG_FLAG(caugthSig));
    } // verify if exist a problem with accept connection
    else if (-1 == fileDescriptorAccept)
    {
      freeaddrinfo(serverInfo); /* Release server info this also free the memory */
      closeFD(fileDescriptorSocket, fileDescriptorAccept);
      genExitError("Failed to accept incoming connections request from listen" , fileDescriptorAccept);
    } // Report the current connection
    else
    {
      srcAddr = &((struct sockaddr_in *)serverInfo->ai_addr)->sin_addr;
      inet_ntop(serverInfo->ai_family, srcAddr, ipStr, sizeof(ipStr));
      snprintf(printStr, sizeof(printStr), "Accepted connection from %s", ipStr);
      syslog(LOG_INFO, "%s",printStr);
      printf("%s\n",printStr);
      // handler Rx and Tx Data
      handlerData(fileDescriptorAccept);
    }
  }
  close(fileDescriptorSocket);
}

static void handlerData(int fileDescriptorAccept)
{
  char * ptrRxTxBuffer = NULL;
  char * ptrRxTxBufferTmp = NULL;
  ssize_t rxSize;
  ssize_t txSize;
  ssize_t totalRxSize = 0;
  bool endfile = false;
  int multiplier = 1;
  int ret;
  int fdFile;
  char *sendBuff;
  size_t bytes2read;

  ptrRxTxBuffer = (char*)calloc(MAX_OUTPUT_STR, sizeof(char));
  if (NULL == ptrRxTxBuffer)
  {
    genExitError("Null pointer received" , 0);
  }

  while (false == endfile)
  {
    rxSize = recv(fileDescriptorAccept, &ptrRxTxBuffer[totalRxSize], (MAX_OUTPUT_STR *  multiplier) - totalRxSize-1, 0);
    if (-1 == rxSize)
    {
      close(fileDescriptorAccept);
      genExitError("Failed to receive incoming connections request from recv" , rxSize);
    }

    fdFile = open(OUT_DIRECTORY, O_RDWR | O_CREAT | O_APPEND, 0666);
    if (-1 == fdFile)
    {
      snprintf(printStr, sizeof(printStr), "Error while creating the new file");
      perror(printStr);
      syslog(LOG_ERR, "%s",printStr);
      genExitError("Error opening the file" , fdFile);
    }

    totalRxSize += rxSize;
    ptrRxTxBuffer[totalRxSize] = '\0';

    if (NULL != strchr(&ptrRxTxBuffer[0], '\n'))
    {
      endfile = true;
    }
    else
    {
      multiplier++;
      ptrRxTxBufferTmp = (char *)realloc(ptrRxTxBuffer, MAX_OUTPUT_STR *  multiplier);
      if (NULL == ptrRxTxBufferTmp)
      {
        genExitError("Null pointer received" , 0);
      }
      else
      {
        ptrRxTxBuffer = ptrRxTxBufferTmp;
      }
    }
  }

  /* Write the input string to file */
  ret = write(fdFile, &ptrRxTxBuffer[0], totalRxSize);
  if (EOF == ret)
  {
    snprintf(printStr, sizeof(printStr), "Failed to update file");
    perror(printStr);
    syslog(LOG_ERR, "%s",printStr);
    genExitError("EOF detected" , ret);
  }


  lseek(fdFile, 0 , SEEK_SET);
  sendBuff = (char *)calloc(MAX_OUTPUT_STR, sizeof(char));
  if(sendBuff == NULL)
  {
    syslog(LOG_INFO, "Client buffer was not allocated hence returning with error");
    genExitError("Bad buffer" , 0);
  }

  // Read and send data
  while ((bytes2read = read(fdFile, sendBuff, MAX_OUTPUT_STR)) > 0) {
    // sendBuff[bytes2read] = '\0';
    txSize = send(fileDescriptorAccept, &sendBuff[0], bytes2read, 0);
    if (-1 == txSize)
    {
      close(fileDescriptorAccept);
      genExitError("Failed to send from send()" , txSize);
    }
  }
  free(sendBuff);
  free(ptrRxTxBuffer);

  close(fdFile);
}