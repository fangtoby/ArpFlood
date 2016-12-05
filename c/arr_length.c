#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argv, char **argc)
{
	char a = 'c';

	printf("%ld \n",sizeof(a));
	printf("%ld \n",sizeof(char));
	printf("%ld \n",sizeof(char *));

	int b = 334;

	printf("%ld \n",sizeof(b));
	printf("%ld \n",sizeof(int));
	printf("%ld \n",sizeof(int *));
	
	printf("%ld \n",sizeof(unsigned int));
	printf("%ld \n",sizeof(int));
	printf("%ld \n",sizeof(double));
	char arr[] = "abcd\0efgh";	
	printf("arr[] array length is %ld\n",strlen(arr));
	printf("arr[] array size of %ld\n",sizeof(arr));
	
	char *iarr[] = {"abc","b","c","d","\0","e","f","g","h"};
	printf("iarr[] array length is %ld\n",strlen(*iarr));
	printf("iarr[] array size of %ld\n",sizeof(iarr));
	exit(1);
}
