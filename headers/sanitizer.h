#ifndef SANITIZER_H
#define SANITIZER_H

#include <stdbool.h>
#include "client-data.h"

void clear_chat_history(data *d); 
void print_chat_history(data *d); 
bool is_valid_input(data *d); 

#endif