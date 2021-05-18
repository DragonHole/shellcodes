#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]){
	int c = 0;
	char *tmp = argv[1];
	while(tmp = strstr(tmp, "x")){
		c++;
		tmp++;
	}

	printf("Length: %d\n", c);

	tmp = argv[1];
	if(strstr(tmp, "x00") == NULL){
		printf("No NULL byte\n");
	}
	else
		printf("There is NULL byte!\n");
	return 0;
}
