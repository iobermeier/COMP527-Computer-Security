#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *gets(char *s); /* removed from the C library, but our copy is in helper.c */

int target_main(int argc, char *argv[])
{
	char grade[5];
	char name[10];

	strcpy(grade, "nil");

	gets(name);

	printf("Hi %s! Your grade is %s.\n", name, grade);
	
	exit(0);	
}
