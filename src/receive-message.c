#include <arpa/inet.h>              
#include <stdbool.h> 

#include "../headers/config.h"
#include "../headers/client-data.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                                   *
 *    buffer: указатель на массив байтов, откуда распаковываем                       *
 *    offset: указатель на текущее смещение в битах (обновляется после распаковки)   *
 *    num_bits: сколько бит нужно распаковать                                        *
 *                                                                                   *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// РАСПАКОВКА БИТОВ
unsigned int unpack_bits(unsigned char* buffer, int* offset, int num_bits) {
    unsigned int value = 0; //>>значение, которое будем собирать
    for (int i = 0; i < num_bits; ++i) {
        // 1. Если бит в буфере по текущему смещению установлен (равен 1)
        if ((buffer[*offset / 8] >> (*offset % 8)) & 0x01) {
            // 2. Устанавливаем соответствующий бит в 'value'
            value |= (1 << i);
        }

        (*offset)++; //>>переходим к следующему биту
    }

    return value;
}

// ЛОГИКА ПОЛУЧЕНИЯ СООБЩЕНИЯ 
void *receive_message(void *arg) {
    ThreadArgsWrapper *wrapper = (ThreadArgsWrapper *)arg;
    
    client_thread_data_t *c = wrapper -> c;
    data *d = wrapper -> d;

    char buffer[1024];
  
    bool isReceived = false;           //>>флаг полученного сообщения
    bool isError    = false;          //>>флаг ошибки
    bool isOverflow = false;         //>>флаг переполнения 

    // ~для распаковки данных
    unsigned char flag;
    uint8_t method;
    unsigned int count_of_messages;
    unsigned int message_size;

    int offset = 0;

    while(1) {
        if(*(c->stop_flag)) {
            break;
        }
        ssize_t bytes_received;    //>>присвоим полученный размер пакета байт (можно int, но лучше ssize_t на случай, если размер превысит размер int)

        if(bytes_received <= 0) {
            if(bytes_received == 0) {
                printf("server closed connected!\n");
            } else {
                if(!*(c->stop_flag)) {
                    perror("error in get data!\n");
                }
            }
            break;
        }
        int offset = 0;
        unsigned char flag = unpack_bits(d->processor_buffer, &offset, FLAG_OVERFLOW_SIZE);
        uint8_t method = unpack_bits(d->processor_buffer, &offset, METHOD_SIZE);
        unsigned int count_of_messages = unpack_bits(d->processor_buffer, &offset, INT_MESSAGE_HISTORY_COUNT);
        unsigned int message_size = unpack_bits(d->processor_buffer, &offset, INT_MESSAGE_HISTORY_COUNT);

        // защита истории
        pthread_mutex_lock(&d->lock);

        if(flag == 1) { // переполнение очищаем историю!
            clear_chat_history(d);
            d->chat_history[0] = malloc(message_size + CONTROL_CHARACTERS);
            d->message_size[0] = message_size;
            memcpy(d->chat_history[0], &d->processor_buffer[HEADER], message_size);
            d->count_of_messages = 1;
        } else { // обычное сообщение
            if(count_of_messages - 1 < HISTORY_MAX_SIZE) {
                d->chat_history[count_of_messages - 1] = malloc(message_size + CONTROL_CHARACTERS);
                d->message_size[count_of_messages - 1] = message_size;
                memcpy(d->chat_history[count_of_messages - 1], &d->processor_buffer[HEADER], message_size);
                d->count_of_messages = count_of_messages;
            }
        }
        if(d->count_of_messages > 0 && d->chat_history[d->count_of_messages -1]) {
            printf("%s\n", d->chat_history[d->count_of_messages -1]);
            fflush(stdout);
        }

        pthread_mutex_unlock(&d->lock);
    }
    return NULL;
}