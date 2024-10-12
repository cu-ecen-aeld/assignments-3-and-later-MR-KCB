#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <syslog.h>


#define EXPECTED_ARGUMENT     (2U)
#define MAX_RX_ARGUMENT       (EXPECTED_ARGUMENT + 1U) /* plus one because we receive the file name in slot 0 */
#define MAX_OUTPUT_STR        (128U)
int main(int argc, char *argv[])
{
  int retVal = 1; //Init with Error Value
  int ret;
  DIR *dir = NULL;
  FILE *fptr = NULL;
  char printStr[MAX_OUTPUT_STR];

  openlog("[LOG Program]", LOG_PID | LOG_NDELAY ,LOG_USER);

  if (MAX_RX_ARGUMENT != argc)
  {
    snprintf(printStr, sizeof(printStr), "Invalid Input Arguments, please use the command  %s <inFile> <inStr>", argv[0]);
    syslog(LOG_ERR, printStr);
  }
  else
  {
#if 0 // Is not required according to the instructions of assignment 2
    *dir = opendir(argv[1]);
    if (NULL == dir)
    {
      if (ENOENT == errno)
      {
        ret = mkdir(argv[1]);
        if (0U != ret)
        {
          snprintf(printStr, sizeof(printStr), "Error while creating the new directory");
          perror(printStr);
          syslog(LOG_ERR, printStr);
        }
      }
      else
      {
        snprintf(printStr, sizeof(printStr), "Something wrong by opendir");
        perror(printStr);
        syslog(LOG_ERR, printStr);
      }
    }
#endif

    fptr = fopen(argv[1], "w+");
    if (NULL == fptr)
    {
      snprintf(printStr, sizeof(printStr), "Error while creating the new file");
      perror(printStr);
      syslog(LOG_ERR, printStr);
    }
    else
    {
      ret = fputs(argv[2], fptr); /* Write the input string to file */
      if (EOF == ret)
      {
        snprintf(printStr, sizeof(printStr), "Failed to update file");
        perror(printStr);
        syslog(LOG_ERR,printStr);
      }
      else
      {
        retVal = 0;
        snprintf(printStr, sizeof(printStr), "Writting %s to %s", argv[2], argv[1]);
        syslog(LOG_DEBUG,printStr);
      }
    }
    fclose(fptr);
  }

  return retVal;
}
