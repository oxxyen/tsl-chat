#ifndef CONFIG
#define CONFIG

#define RED "\x1B[31m"          //>>вывод красного цвета
#define GRN "\x1B[32m"         //>>вывод зеленого цвета
#define YEL "\x1B[33m"        //>>вывод желтого цвета
#define BLU "\x1B[34m"       //>>вывод синего цвета
#define RESET "\x1B[0m"     //>>вывод по умолчанию (сброс цвета)

#define HISTORY_MAX_SIZE 100                       //>>максимальное кол-во сообщений в истории
#define MAX_MSG_LEN 1024                          //>>максимальное кол-во символов в сообщении 

#define FLAG_OVERFLOW_SIZE 1                    //(БИТ) -> флаг переполнения 
#define METHOD_SIZE 4                          //(БИТ) -> метод
#define INT_MESSAGE_SIZE 11                   //(БИТ) -> размер сообщения
#define INT_MESSAGE_HISTORY_COUNT 7          //(БИТ) -> кол-во сообщений в истории
    #define TOTAL_SIZE (FLAG_OVERFLOW_SIZE + METHOD_SIZE + INT_MESSAGE_SIZE + INT_MESSAGE_HISTORY_COUNT) //>>сумма зарезервированных битов


#define CONTROL_CHARACTERS 2                //>>управляющий символ (\n или \0)

#define HEADER ((TOTAL_SIZE) / 8 + (TOTAL_SIZE % 8 != 0 ? 1: 0))            //>>размер заголовка (в среднем 3 байта)
#define RESERVED (HEADER + CONTROL_CHARACTERS) 
#define ARRANGEMENT_BUFFER_SIZE (RESERVED + (MAX_MSG_LEN * sizeof(char)))          //>>размер буфера для введенного сообщения 
#define PROCESSOR_BUFFER_SIZE (RESERVED + (MAX_MSG_LEN * sizeof(char)))           //>>размер буфера для входящих данных из "трубы"

#define RECONNECT_INTERVAL 5     //>>интервал переподключения в секундах
#define RECREATE_INTERVAL 2     //>>интервал пересоздания сокета 
#define ERROR_TIMEOUT 2        //>>интервел в случае ошибки

#define SOCKET -1
#define IP "127.0.0.1"
#define PORT 8080

#endif // CONFIG_H