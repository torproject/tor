/*
 * scheduler.h
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
 * Revision 1.2  2002/03/28 10:49:07  badbytes
 * Renamed get_trigger() to sched_trigger().
 *
 * Revision 1.1  2002/03/28 10:36:55  badbytes
 * A generic scheduler.
 *
 */

#ifndef __SCHEDULER_H

#include <sys/time.h>

typedef struct 
{
  struct timeval last;
  struct timeval interval;
  void *prev;
  void *next;
} sched_entry_t;

typedef struct
{
  sched_entry_t *entries;
} sched_t;

/* create a new scheduler */
sched_t *new_sched();
/* delete a scheduler from memory */
void free_sched(sched_t *sched);

/* add a new item to the scheduler */
int add_sched_entry(sched_t *sched, struct timeval last, struct timeval interval);
/* remove an item from the scheduler */
int remove_sched_entry(sched_t *sched, struct timeval last, struct timeval interval);
/* update an existing item with new values */
int update_sched_entry(sched_t *sched, struct timeval old_last, struct timeval old_interval, struct timeval new_last, struct timeval new_interval);

/* get the time interval from now until the next time an item needs to be serviced */
int sched_trigger(sched_t *sched, struct timeval **result);
/* compare two scheduler entries (returns 1 if entry1 >= entry2, 0 otherwise */
int sched_entry_geq(struct timeval last1, struct timeval interval1, struct timeval last2, struct timeval interval2);

# define __SCHEDULER_H
#endif
