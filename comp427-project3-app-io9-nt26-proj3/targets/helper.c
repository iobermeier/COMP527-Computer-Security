#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define STACK_GOAL 0xFFFF0000U
#define MAX_PAD 0xFFFF

/* Read a newline-terminated string from stdin into S,
   removing the trailing newline.  Return S or NULL.  */
char *gets(char *s)
{
	/* gets() was removed from the standard C libraries because it's wildly insecure.
	   We're including it here so you can attack it. */
	register char *p = s;
	register int c;
	FILE *stream = stdin;
	if (p == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	if (feof(stream) || ferror(stream))
		return NULL;
	while ((c = getchar()) != EOF)
		if (c == '\n')
			break;
		else
			*p++ = c;
	*p = '\0';
	/* Return null if we had an error, or if we got EOF
	   before writing any characters.  */
	if (ferror(stream) || (feof(stream) && p == s))
		return NULL;
	return s;
}

int target_main(int argc, char *argv[], char *envp[]); // implemented for each target

int main(int argc, char *argv[], char *envp[])
{
	volatile int canary = 0xDEADBEEF;

	// Advance the stack pointer to a position that's invariant of
	// the size of the environment and the program arguments.
	char *esp = alloca(0);
	if ((esp < (char *)STACK_GOAL) || (esp - (char *)STACK_GOAL > MAX_PAD)) {
		fprintf(stderr, "Can't normalize stack position: %p\n", esp);
		return 1;
	}
	alloca(esp - (char *)STACK_GOAL);
#ifdef COOKIE
	alloca(COOKIE);
#endif

	int ret = target_main(argc, argv, envp);

	if (canary != 0xDEADBEEF) {
		fprintf(stderr, "Uh oh, the canary is dead.\n" \
				"Don't overwrite the stack frame for main().\n");
	}
	return ret;
}
