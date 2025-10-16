#include <arpa/inet.h>              
#include <string.h>

#include "../headers/command-type.h"



// ИСПОЛЬЗУЕМ ENUM НАПРЯМУЮ БЕЗ ДУБЛИРОВАНИЯ 
const CommandMapping command_map[] = {
    {"SEND", CMD_SEND},
    // {"ADD",  CMD_ADD},
    // {"ASK",  CMD_ASK},
    // {"PING", CMD_PING},
};

// ВОЗВРАЩАЕМ КОД МЕТОДА
uint8_t get_code(const char* method_name) {

   /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
    *                                                                       *
    *    1. Количество элементов в command_map                              *
    *    sizeof(command_map) - общий размер массива в байтах                *
    *    sizeof(command_map[0]) - размер одного элемента массива в байтах   *
    *    Делим одно на другое, чтобы получить количество элементов          *
    *                                                                       *
    * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    size_t num_commands = sizeof(command_map) / sizeof(command_map[0]);

    for (size_t i = 0; i < num_commands; ++i) {
        
        if (strcmp(method_name, command_map[i].name) == 0) {
            return command_map[i].code;   //>>возвращаем код прямо из enum
        }
    }

    // 2. Если команда не найдена, возвращаем код для неизвестной команды
    return CMD_UNKNOWN;
}

// ПОЛУЧАЕМ НАЗВАНИЕ МЕТОДА ПО ПОЛУЧЕННОМУ КОДУ
const char* get_method(CommandType code) {
    // 1. Получаем код по размеру
    size_t num_commands = sizeof(command_map) / sizeof(command_map[0]);
    
    for (size_t i = 0; i < num_commands; ++i) {
        if (command_map[i].code == code) {       //>>сравниваем код
            return command_map[i].name;         //>>возвращаем имя
        }
    }

    // 2. Если код не найден, возвращаем "UNKNOWN"
    return "UNKNOWN";
}


