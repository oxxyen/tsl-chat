#include <stdint.h> 

#ifndef COMMAND_TYPE_H
#define COMMAND_TYPE_H

typedef enum {
    CMD_SEND,   
    CMD_UNKNOWN,
} CommandType;

typedef struct {
    const char* name;
    CommandType code;
} CommandMapping;

extern const CommandMapping command_map[]; 

uint8_t get_code(const char* method_name); 
const char* get_method(CommandType code);

#endif 

