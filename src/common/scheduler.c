/*
 * scheduler.c
 * Scheduler
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.3  2002/04/02 10:20:37  badbytes
 * Bug fixes.
 *
 * Revision 1.2  2002/03/28 10:49:07  badbytes
 * Renamed get_trigger() to sched_trigger().
 *
 * Revision 1.1  2002/03/28 10:36:55  badbytes
 * A generic scheduler.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include "log.h"
#include "scheduler.h"

/* create a new scheduler */
sched_t *new_sched()
{
  sched_t *sched;
  
  sched = (sched_t *)malloc(sizeof(sched_t));
  if (!sched)
    return NULL;
  
  sched->entries = NULL;
  return sched;
}

/* delete a scheduler from memory */
void free_sched(sched_t *sched)
{
  sched_entry_t *entry;
  if (!sched)
    return;
  
  while(sched->entries)
  {
    entry = (sched_entry_t *)sched->entries->next;
    free((void *)sched->entries);
    sched->entries = entry;
  }
}

/* add a new item to the scheduler */
int add_sched_entry(sched_t *sched, struct timeval last, struct timeval interval)
{
  sched_entry_t *new_entry;
  sched_entry_t *prev;
  sched_entry_t *next;
  
  if (!sched) /* invalid parameters */
    return -1;
  
  new_entry = (sched_entry_t *)malloc(sizeof(sched_entry_t));
  if (!new_entry)
    return -1;
  
  new_entry->last = last;
  new_entry->interval = interval;
  
  if (!sched->entries) /* empty list */
  {
    sched->entries = new_entry;
    new_entry->prev = NULL;
    new_entry->next = NULL;
  }
  else /* maintain a priority queue of items */
  {
    /* find the next largest element in the list */
    next = sched->entries;
    while(next)
    {
      if (sched_entry_geq(next->last, next->interval, last, interval))
      {
	prev = (sched_entry_t *)next->prev;
	break;
      }
      else
      {
	prev = next;
	next = (sched_entry_t *)next->next;
      }
    }
    
    if (prev)
      prev->next = (void *)new_entry;
    else
      sched->entries = new_entry;
    
    if (next)
      next->prev = (void *)new_entry;
    
    new_entry->prev = (void *)prev;
    new_entry->next = (void *)next;
  }
  
  return 0;
}

int remove_sched_entry(sched_t *sched, struct timeval last, struct timeval interval)
{
  sched_entry_t *entry;
  
  if (!sched)
    return -1;

 if (!sched->entries)
    return -1;
  
  entry = sched->entries;
  while(entry)
  {
    if ((entry->last.tv_sec == last.tv_sec) && (entry->last.tv_usec = last.tv_usec) && (entry->interval.tv_sec == interval.tv_sec) && (entry->interval.tv_usec == interval.tv_usec))
    {
      if (entry->prev)
	((sched_entry_t *)(entry->prev))->next = entry->next;
      else
	sched->entries = (sched_entry_t *)entry->next;
      
      if (entry->next)
	((sched_entry_t *)(entry->next))->prev = entry->prev;
      
      free((void *)entry);
      break;
    }
    else
      entry = (sched_entry_t *)entry->next;
  }
  
  if (entry) /* found and deleted */
    return 0;
  else /* not found */
    return -1;
}

/* update an existing item with new values */
int update_sched_entry(sched_t *sched, struct timeval old_last, struct timeval old_interval, struct timeval new_last, struct timeval new_interval)
{
  int retval;
  
  if (!sched)
    return -1;
  
  /* remove the old entry first */
  retval = remove_sched_entry(sched, old_last, old_interval);
  if (!retval)
  {
    /* add the new one */
    retval = add_sched_entry(sched, new_last, new_interval);
  }
  
  return retval;
}

/* get the time interval from now until the next time an item needs to be serviced */
int sched_trigger(sched_t *sched, struct timeval **result)
{
  int retval;
  struct timeval *result_val;
  struct timeval now;
  struct timeval next;
  
  if (!sched) /* invalid parameters */
    return -1;
  
  if (!sched->entries) /* no entries */
  {
    *result = NULL;
    return 0;
  }
  
  /* take the minimum element in the queue and calculate its next service time */
  next.tv_sec = sched->entries->last.tv_sec + sched->entries->interval.tv_sec;
  if (sched->entries->last.tv_usec + sched->entries->interval.tv_usec <= 999999)
    next.tv_usec = sched->entries->last.tv_usec + sched->entries->interval.tv_usec;
  else
  {
    next.tv_sec++;
    next.tv_usec = sched->entries->last.tv_usec + sched->entries->interval.tv_usec - 1000000;
  }

  /* get current time */
  retval = gettimeofday(&now,NULL);
  if (retval == -1)
    return -1;
  
  /* allocate memory for the result */
  result_val = (struct timeval *)malloc(sizeof(struct timeval));
  if (!result_val)
    return -1;
  
  /* subtract now from next (return zero if negative) */
  if ((next.tv_sec > now.tv_sec) || ((next.tv_sec == now.tv_sec) && (next.tv_usec >= now.tv_usec)))
  {
    result_val->tv_sec = next.tv_sec - now.tv_sec;
    if (next.tv_usec >= now.tv_usec)
      result_val->tv_usec = next.tv_usec - now.tv_usec;
    else
    {
      result_val->tv_sec--;
      result_val->tv_usec = 1000000 + next.tv_usec - now.tv_usec;
    }
  }
  else /* next service time has already passed, return a timeout of zero */
  {
    result_val->tv_sec = 0;
    result_val->tv_usec = 0;
  }

  *result = result_val;
  
  return 0;
}

int sched_entry_geq(struct timeval last1, struct timeval interval1, struct timeval last2, struct timeval interval2)
{
  struct timeval next1;
  struct timeval next2;
  
  /* calculate next service time for entry1 */
  next1.tv_sec = last1.tv_sec + interval1.tv_sec;
  if (last1.tv_usec + interval1.tv_usec <= 999999)
    next1.tv_usec = last1.tv_usec + interval1.tv_usec;
  else
  {
    next1.tv_sec++;
    next1.tv_usec = last1.tv_usec + interval1.tv_usec - 1000000;
  }
  
  /* calculate next service time for entry2 */
  next2.tv_sec = last2.tv_sec + interval2.tv_sec;
  if (last2.tv_usec + interval2.tv_usec <= 999999)
    next2.tv_usec = last2.tv_usec + interval2.tv_usec;
  else
  {
    next2.tv_sec++;
    next2.tv_usec = last2.tv_usec + interval2.tv_usec - 1000000;
  }
  
  /* compare */
  if ((next1.tv_sec > next2.tv_sec) || ((next1.tv_sec == next2.tv_sec) && (next1.tv_usec >= next2.tv_usec)))
    return 1;
  else
    return 0;
}
