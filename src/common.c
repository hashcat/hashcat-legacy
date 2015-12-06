/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"

#define MSG_ENOMEM "Insufficient memory available"

void dump_hex (const char *s, size_t size)
{
  size_t i;

  for (i = 0; i < size; i++)
  {
    printf ("%02x ", (unsigned char) s[i]);
  }

  printf ("\n");
}

void log_msg (FILE *fp, const char *fmt, va_list ap)
{
  vfprintf (fp, fmt, ap);

  fprintf (fp, "\n");
}

void log_info (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  log_msg (stdout, fmt, ap);

  va_end (ap);
}

void log_warning (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  log_msg (stderr, fmt, ap);

  va_end (ap);
}

void log_error (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  fprintf (stderr, "\n\n");

  log_msg (stderr, fmt, ap);

  va_end (ap);
}

uint32_t get_random_num (uint32_t min, uint32_t max)
{
  if (min == max) return (min);

  return ((rand () % (max - min)) + min);
}

void *mycalloc (size_t nmemb, size_t size)
{
  void *p = calloc (nmemb, size);

  if (p == NULL)
  {
    log_error ("%s", MSG_ENOMEM);

    exit (-1);
  }

  return (p);
}

void *mymalloc (size_t size)
{
  void *p = malloc (size);

  if (p == NULL)
  {
    log_error ("%s", MSG_ENOMEM);

    exit (-1);
  }

  return (p);
}

void *malloc_tiny (const size_t size)
{
  // this alloc system reduced the number of memory fragment drastically

  #define MEM_ALLOC_SIZE 0x10000

  if (size > MEM_ALLOC_SIZE)
  {
    // we can't handle it here

    return mymalloc (size);
  }

  static char *buffer  = NULL;
  static size_t bufree = 0;

  if (size > bufree)
  {
    buffer = mymalloc (MEM_ALLOC_SIZE);
    bufree = MEM_ALLOC_SIZE;
  }

  char *p = buffer;

  buffer += size;
  bufree -= size;

  return p;
}

void myfree (void *ptr)
{
  free (ptr);
}

void *myrealloc (void *ptr, size_t size)
{
  void *p = realloc (ptr, size);

  if (p == NULL)
  {
    log_error ("%s", MSG_ENOMEM);

    exit (-1);
  }

  return (p);
}

char *mystrdup (const char *s)
{
  char *b = mymalloc (strlen (s) + 1);

  strcpy (b, s);

  return (b);
}

int in_superchop (char *buf)
{
  int len = strlen (buf);

  while (len)
  {
    if (buf[len - 1] == '\n')
    {
      len--;

      continue;
    }

    if (buf[len - 1] == '\r')
    {
      len--;

      continue;
    }

    break;
  }

  buf[len] = 0;

  return len;
}
