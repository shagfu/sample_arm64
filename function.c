#include <stdio.h>
int strcmp(char *a, char *b)
{
    //get length
    int len = 0;
    char *ptr = a;
    while(*ptr)
    {
        ptr++;
        len++;
    }

    //comparestrings
    for(int i=0; i<=len; i++)
    {
        if (a[i]!=b[i])
            return 1;
    }

    return 0;
}

__attribute__((stdcall))
int  super_function(int a, char *b)
{
    if (a==5 && !strcmp(b, "batman"))
    {
        return 1;
    }
    return 0;
}

int main()
{
    super_function(1, "spiderman");
}