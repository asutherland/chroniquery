#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ll
{
  char *value;
  struct ll *next;
};

typedef struct ll ll;

typedef char bool;
#define true 1
#define false 0

ll *cons(char *a, ll *tail)
{
  ll *buildy = (ll *)malloc(sizeof(ll));
  buildy->value = a;
  buildy->next = tail;

  return buildy;
}

void print_list(ll *list, bool first, bool newline)
{
  if(list != NULL)
  {
    if(!first) printf(", ");
    printf("%s", list->value);

    print_list(list->next, false, false);
  }

  if (newline) printf("\n");
}

int nuke(ll **plist, char *val)
{
  ll *cll, *last;
  for(cll = *plist, last=NULL; cll != NULL; last=cll, cll = cll->next)
  {
    if(strcmp(cll->value, val) == 0)
    {
      if(last == NULL)
      {
        *plist = cll->next;
      }
      else
      {
        last->next = cll->next;
      }
      free(cll);

      return 0;
    }
  }
  return 1;
}

ll *favorite_colors;

int main(int argc, char **argv)
{
  favorite_colors = cons("red", cons("green", cons("blue", NULL)));

  print_list(favorite_colors, true, true);
  nuke(&favorite_colors, "never existed");
  nuke(&favorite_colors, "green");
  print_list(favorite_colors, true, true);
  nuke(&favorite_colors, "green");
  nuke(&favorite_colors, "blue");
  print_list(favorite_colors, true, true);
}
