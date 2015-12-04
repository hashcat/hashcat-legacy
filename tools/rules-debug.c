/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "rp.h"

#define INCR_RULES_PTR 1

int compare_string (const void *p1, const void *p2)
{
  const char *s1 = (const char *) p1;
  const char *s2 = (const char *) p2;

  return strcmp (s1, s2);
}

void incr_rules_buf (rules_t *rules)
{
  if (rules->rules_cnt == rules->rules_avail)
  {
    rules->rules_avail += INCR_RULES_PTR;

    rules->rules_buf = myrealloc (rules->rules_buf, rules->rules_avail * sizeof (char *));

    rules->rules_len = myrealloc (rules->rules_len, rules->rules_avail * sizeof (uint32_t));
  }
}

int fgetl (FILE *fp, char *line_buf)
{
  if (fgets (line_buf, BLOCK_SIZE, fp) == NULL) return (-1);

  int line_len = strlen (line_buf);

  if (line_buf[line_len - 1] == '\n')
  {
    line_len--;

    line_buf[line_len] = '\0';
  }

  if (line_buf[line_len - 1] == '\r')
  {
    line_len--;

    line_buf[line_len] = '\0';
  }

  return (line_len);
}

void *root = NULL;

int add_rule (char *rule_buf, int rule_len, rules_t *rules)
{
  if (tfind (rule_buf, &root, compare_string) != NULL) return (-3);

  char in[BLOCK_SIZE];
  char out[BLOCK_SIZE];

  memset (in,  0, BLOCK_SIZE);
  memset (out, 0, BLOCK_SIZE);

  int result = apply_rule (rule_buf, rule_len, in, 1, out);

  if (result == -1) return (-1);

  char *next_rule = mystrdup (rule_buf);

  tsearch (next_rule, &root, compare_string);

  incr_rules_buf (rules);

  rules->rules_buf[rules->rules_cnt] = next_rule;

  rules->rules_len[rules->rules_cnt] = rule_len;

  rules->rules_cnt++;

  return (0);
}

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "usage: %s rules-file\n", argv[0]);

    return (-1);
  }

  rules_t *rules = malloc (sizeof (rules_t));

  memset (rules, 0, sizeof (rules_t));

  char *file_rules;

  if ((file_rules = argv[1]) != NULL)
  {
    FILE *fp;

    if ((fp = fopen (file_rules, "rb")) != NULL)
    {
      char rule_buf[RP_RULE_BUFSIZ];

      int rule_len;

      while ((rule_len = fgetl (fp, rule_buf)) != -1)
      {
        if (rule_len == 0) continue;

        if (rule_buf[0] == '#') continue;

        int rc = add_rule (rule_buf, rule_len, rules);

        if (rc == 0)
        {
          /* all ok */
        }
        else if (rc == -1)
        {
          fprintf (stderr, "Skipping rule: %s (syntax error)\n", rule_buf);
        }
        else if (rc == -3)
        {
          fprintf (stderr, "Skipping rule: %s (duplicate rule)\n", rule_buf);
        }
        else if (rc == -4)
        {
          fprintf (stderr, "Skipping rule: %s (duplicate result)\n", rule_buf);
        }
      }

      fclose (fp);
    }
    else
    {
      fprintf (stderr, "%s: %s\n", file_rules, strerror (errno));

      free (rules);

      return (-1);
    }
  }

  char word_buf[BLOCK_SIZE];

  int word_len;

  while ((word_len = fgetl (stdin, word_buf)) != -1)
  {
    uint32_t rules_idx;

    for (rules_idx = 0; rules_idx < rules->rules_cnt; rules_idx++)
    {
      char next_buf[BLOCK_SIZE];

      int next_len = apply_rule (rules->rules_buf[rules_idx], rules->rules_len[rules_idx], word_buf, word_len, next_buf);

      if (next_len < 0) continue;

      puts (next_buf);
    }
  }

  return 0;
}
