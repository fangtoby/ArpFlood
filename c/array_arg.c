#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_arr_str(char arr[], int);

void change_arr_str(char arr[],char,int);

void change_arr_str_other(char * arr,char,int);

int main(int argv, char **argc)
{
	char arr[10];
	int arr_len = sizeof(arr);
	int i;

	for(i=0;i<arr_len;i++){
		arr[i] = 'b';
	}
	print_arr_str(arr,arr_len);

	char char_c = 'c';

	change_arr_str(arr, char_c,arr_len);

	print_arr_str(arr,arr_len);

	char char_d = 'd';

	change_arr_str_other(arr,char_d,arr_len);

	print_arr_str(arr, arr_len);

	exit(0);
}
void print_arr_str(char arr[], int len)
{
	int temp;
	for(temp=0;temp<len;temp++){
		printf("arr[%d] = %c\n",temp,arr[temp]);
	}
}
void change_arr_str(char arr[],char replaceStr, int len)
{
	int temp;
	for(temp=0;temp<len;temp++){
		arr[temp] = replaceStr;
	}
}
void change_arr_str_other(char * arr,char replaceStr, int len)
{
	int temp;
	for(temp=0;temp<len;temp++){
		arr[temp] = replaceStr; 
	}
}
