#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t *q)
{
  return (q->size <= 0);
}

int full(struct queue_t *q)
{
  return (q->size >= MAX_QUEUE_SIZE);
}

void enqueue(struct queue_t *q, struct pcb_t *proc)
{
  /* Put a new process to queue [q] */

  if (empty(q))
  {
    q->proc[0] = proc;
    (q->size) = 1;
    return;
  }

  if (full(q))
  {
    printf("Queue overflow");
    exit(1);
  }

  for (int i = q->size; i > 0; i -= 1)
  {
    if (q->proc[i - 1]->priority <= proc->priority)
    {
      q->proc[i] = proc;
      i = -1;
    }
    else
      q->proc[i] = q->proc[i - 1];

    if (i == 1)
      q->proc[0] = proc;
  }

  (q->size) += 1;
  return;
}

struct pcb_t *dequeue(struct queue_t *q)
{
  /*
   * Return a pcb whose priority is the highest
   * in the queue [q] and remember to remove it from q
   */

  if (q->size <= 0)
    return NULL;

  if (q->size >= MAX_QUEUE_SIZE) // * As if this will ever happen
    ;

  struct pcb_t *result = q->proc[0];

  for (int i = 0; i < q->size; i += 1)
    q->proc[i] = q->proc[i + 1];

  q->size -= 1;
  q->proc[q->size] = NULL;
  return result;
}
