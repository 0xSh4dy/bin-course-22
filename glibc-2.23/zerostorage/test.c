#include<stdio.h>
#include<stdlib.h>
int main(){
 void* ptr1 = malloc(0x28);
 void* ptr2 = malloc(0x28);
 void* ptr3 = malloc(0x88);
 free(ptr1);
 free(ptr2);
 free(ptr3);
 return 0;
}
