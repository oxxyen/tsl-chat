#ifndef SEND_MESSAGE
#define SEND_MESSAGE

void *send_message(void *arg);
void pack_bits(unsigned char* buffer, int* offset, unsigned int value, int num_bits);

#endif
