#include <stdio.h>
#include <stdlib.h>

void f(int *t){
    int *a = (int*)malloc(16);
    t = a;
}
// the pointer not free and assign again
int main(){
    int *t;
    f(t);
    t = (int*)malloc(16);
    free(t);
    return 0;
}