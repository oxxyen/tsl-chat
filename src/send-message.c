#include <stdio.h>
#include <stdbool.h>                        //>>использование типа boolean (true/false за место 1/0)
#include <arpa/inet.h>              

#include "../headers/config.h"
#include "../headers/client-data.h"
#include "../headers/sanitizer.h"
#include "../headers/command-type.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 *                                                                               *
 *    Устанавливаем соответствующий бит в буфере по текущему смещению            *
 *    arrangement_buffer[*bit / 8] - это текущий байт в массиве                           *
 *    (1 << (*bit % 8)) - это маска для установки нужного бита в этом байте   *
 *                                                                               *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// УПАКОВКА БИТОВ 
void pack_bits(unsigned char* arrangement_buffer, int* bit, unsigned int value, int reserved_bits) {
    for (int i = 0; i < reserved_bits; ++i) {
        // 1. Если i-й бит в 'value' установлен (равен 1)
        if ((value >> i) & 0x01) {
            arrangement_buffer[*bit / 8] |= (1 << (*bit % 8));
        }

        (*bit)++;    //>>переходим к следующему биту
    }
}

// ЛОГИКА ОТПРАВКИ СООБЩЕНИЙ
void *send_message(void *arg) {
    ThreadArgsWrapper *wrapper = (ThreadArgsWrapper *)arg;
    
    client_thread_data_t *c = wrapper -> c;
    data *d = wrapper -> d;
    
    bool isSended   = false;           //>>флаг отправленного сообщения
    bool isError    = false;          //>>флаг ошибки
    bool isOverflow = false;         //>>флаг переполнения 

    // ~данные для отправки
    unsigned char flag;                  // <~ бинарный флаг переполнения 
    uint8_t method;                     // <~ код метода  
    unsigned int count_of_messages;    // <~ кол-во сообщений 
    unsigned int message_size;        // <~ размер отправляемого сообщения 

    // int current_len = 0;   //>>длина введенного сообщения 
    int bit = 0;             //>>текущий бит
    
/*лок*/ pthread_mutex_lock(&d -> lock); 

    // 1. Обрабатываем пользовательский ввод с stdin 
    if (!is_valid_input(d)) { 
        pthread_exit(NULL);

        isError = true;
        return NULL;
    }
    
/*анлок*/ pthread_mutex_unlock(&d -> lock);

    // 2. Проверяем, не переполнена ли история 
    if (d -> count_of_messages == HISTORY_MAX_SIZE) isOverflow = true;  // !чистим историю в is_valid_input(), тут выставляем флаг

    // 3. Подготавливаем данные к отправке. Пакет: [flag][method][msg_count][msg_size][msg] - в msg попадает содержимое stdin_buffer
    flag = isOverflow ? 1 : 0;
    method = get_code("SEND");
    count_of_messages = d -> count_of_messages;
    message_size = d -> message_size[d -> count_of_messages]; 


    //              --- УПАКОВКА ---              //
    pack_bits(d -> arrangement_buffer, &bit, flag, 1);
    pack_bits(d -> arrangement_buffer, &bit, method, 7);
    pack_bits(d -> arrangement_buffer, &bit, count_of_messages, 11);
    pack_bits(d -> arrangement_buffer, &bit, message_size, 4);

    memcpy(d -> arrangement_buffer + 3, d -> stdin_buffer, d -> message_size[d -> count_of_messages - 1]);

    
    //              --- ОТПРАВКА ---              //
    while (!isSended && !isError) {
        if (send(c -> client_socket, d -> arrangement_buffer, sizeof(d -> arrangement_buffer), 0) < 0) {
            printf("could not send message");
            
            isError = true;  // -> лучше как-то обрабатывать в сл. версиях 
            break;
        }

        isSended = true;
    }

    pthread_exit(NULL); //>>завершаем поток
    return NULL;
}