#include <cstdio>
#include <cstdlib>
#include <cstring>

struct ll
{
  char *value;
  ll *next;
};

ll *cons(char *a, ll *tail)
{
  ll *buildy = new ll;
  buildy->value = a;
  buildy->next = tail;

  return buildy;
}

void print_list(ll *list, bool first=true, bool newline=true)
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
  ll *last = NULL;
  for(ll *cll = *plist, *last=NULL; cll != NULL; last=cll, cll = cll->next)
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
      delete cll;

      return 0;
    }
  }
  return 1;
}

ll *favorite_colors;

int smain(int argc)
{
  favorite_colors = cons("red", cons("green", cons("blue", NULL)));

  print_list(favorite_colors);
  nuke(&favorite_colors, "never existed");
  nuke(&favorite_colors, "green");
  print_list(favorite_colors);
  nuke(&favorite_colors, "green");
  nuke(&favorite_colors, "blue");
  print_list(favorite_colors);
}

int main(int argc, char **argv)
{
   char *dummy = new char[16];
   return smain(argc);
}
