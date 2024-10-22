#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define PRINT_LINE()       printf("====================================================\n")
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)
#define MS_TO_US(x)        (x * 1000)

void* threadfunc(void* thread_param)
{

  // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
  // hint: use a cast like the one below to obtain thread arguments from your parameter
  //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
  struct thread_data* ptrThData = (struct thread_data *) thread_param;
  int status = 0;

  ptrThData->thread_complete_success = false;
  usleep(MS_TO_US(ptrThData->wait_to_obtain_ms));

  status = pthread_mutex_lock(ptrThData->mutex);
  if (0 == status)
  {
    usleep(MS_TO_US(ptrThData->wait_to_release_ms));
    status = pthread_mutex_unlock(ptrThData->mutex);
    if (0 == status)
    {
      ptrThData->thread_complete_success = true;
    }
    else
    {
      PRINT_LINE();
      DEBUG_LOG("[DEBUG] pthread_mutex_unlock status %d", status);
      PRINT_LINE();
    }
  }
  else
  {
    PRINT_LINE();
    DEBUG_LOG("[DEBUG] pthread_mutex_lock status %d", status);
    PRINT_LINE();
  }

  return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
  /**
  * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
  * using threadfunc() as entry point.
  *
  * return true if successful.
  *
  * See implementation details in threading.h file comment block
  */

  struct thread_data * ptrThData = (struct thread_data *)malloc(sizeof(struct thread_data));
  int ptreadSts;


  if (NULL == ptrThData)
  {
    return false;
  }

  ptrThData->mutex = mutex;
  ptrThData->wait_to_obtain_ms = wait_to_obtain_ms;
  ptrThData->wait_to_release_ms = wait_to_release_ms;
  ptrThData->thread_complete_success = false;

  ptreadSts = pthread_create(thread, NULL, threadfunc, ptrThData);
  PRINT_LINE();
  DEBUG_LOG("[DEBUG] Thread create status %d", ptreadSts);
  PRINT_LINE();
  
  ptreadSts = (0 != ptreadSts) ? (false) : (true);

  return ptreadSts;
}

