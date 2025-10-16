#include <pthread.h>              
#include <arpa/inet.h>   
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "sanitizer.h"

#ifndef CLIENT_DATA
#define CLIENT_DATA


// СТРУКТУРА СЕТЕВЫХ НАСТРОЕК
typedef struct {
    int client_socket;
    char *server_ip;
    int port;
    volatile sig_atomic_t* stop_flag;
} client_thread_data_t;

// СТРУКТУРА ХРАНЕНИЯ ИСТОРИИ СООБЩЕНИЙ
typedef struct {
/*общая история*/
    int count_of_messages;  //>>он же индекс сообщения в массиве указателей 

    char *chat_history[HISTORY_MAX_SIZE];  //>>массив указателей. Указатель = начало отправленного сообщения
    int message_size[HISTORY_MAX_SIZE];   //>>размер выделенной памяти каждого сообщения. Индекс соответствет индексу сообщения 

    // выделяем память в куче
    char *stdin_buffer;
    char *arrangement_buffer;
    uint8_t *processor_buffer;

    pthread_mutex_t lock;   //>>мютекс
    
} data;

// !ДЛЯ ПОТОКА, ХРАНИМ УКАЗАТЕЛИ ДЛЯ ДВУХ СТРУКТУР
typedef struct {
    client_thread_data_t *c; //>>указатель на структуру сетевых настроек
    data *d;             //>>указатель на структуру хранения сообщений
} ThreadArgsWrapper;

#endif

// !ОБЪЯВЛЕНИЯ ФУНКЦИЙ 
// объявления функций вывода и добавления историй -> src/client-data.
void print_chat_history(data *d);
void add_message_to_history(data *d, const char *mg);