#ifndef RECEIVE_MESSAGE
#define RECEIVE_MESSAGE

void *receive_message(void *arg);
unsigned int unpack_bits(unsigned char* buffer, int* offset, int num_bits);

#endif