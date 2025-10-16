
#define _GNU_SOURCE

#include <stdio.h>                            
#include <stdlib.h>                         
#include <stdbool.h>                        
#include <string.h>                      
#include <ctype.h>                       
#include <regex.h>                      
#include <limits.h>                     
#include <math.h>                      
#include <time.h>                     
#include <arpa/inet.h>               
#include <sys/socket.h>             
#include <netinet/in.h>            
#include <pthread.h>             
#include <unistd.h>
#include <signal.h>

//>> ЗАГОЛОВКИ ПОДКЛЮЧАЕМ В ПРАВИЛЬНОМ ПОРЯДКЕ:
//>> сначала config.h (содержит константы),
//>> затем client-data.h (определяет структуру data),
//>> потом остальные, которые от него зависят

#include "../headers/config.h"          //>>содержит IP, PORT, SOCKET и др.
#include "../headers/client-data.h"     //>>определяет структуру data
#include "../headers/command-type.h"
#include "../headers/sanitizer.h"       //>>теперь знает о data
#include "../headers/receive-message.h"
#include "../headers/send-message.h"

//>> УБРАЛИ ШИФРОВАНИЕ, потому что сервер работает в открытом виде
// #include "../crypto/crypto.h"  //>>закомментировано — не используется

//>> ГЛОБАЛЬНЫЙ ФЛАГ ПОДКЛЮЧЕНИЯ
volatile int connected = 1;

volatile sig_atomic_t stop_client = 0;

void handle_signal(int sig) {
    stop_client = 1;
}

// СОЗДАЕМ СОКЕТ, ПЫТАЕМСЯ ПОДКЛЮЧИТЬСЯ КО ВТОРОМУ УЧАСТНИКУ 
int main() {
    data d = {0};    //>>заполняем все нулями, включая мютекс


    client_thread_data_t c;
    ThreadArgsWrapper thread_args_wrapper;
    struct sockaddr_in server_addr;
    signal(SIGINT, handle_signal);

    // ~инициализируем поля
    pthread_mutex_init(&d.lock, NULL);  //>>инициализируем мютекс

    c.client_socket = SOCKET;        //>>перед созданием сокета присваиваем константное значение (чтобы не хранить мусор)
    c.server_ip = strdup(IP);       //>>IP константный 
    c.port = PORT;                 //>>аналогично с портом 

    thread_args_wrapper.c = &c;    //>>для потоков нам необходимо передавать 1 структуру
    thread_args_wrapper.d = &d;   //   поэтому будем хранить 2 указателя на нужные нам структуры в отдельной 
    
    bool isCreated   = false;      //>>флаг создания сокета (true = успешно создан)
    bool isConnected = false;     //>>флаг подключения (пока true = есть активное подключение)
    bool isError     = false;    //>>флаг ошибки


       /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
        *                                                                 *
        *    параметры сокета для клиента                                 * 
        *    AF_INET: IPv4                                                *
        *    SOCK_STREAM: TCP                                             *
        *    0: протокол по умолчанию (TCP для AF_INET/SOCK_STREAM)       *
        *                                                                 *
        * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    d.stdin_buffer = malloc(MAX_MSG_LEN);
    d.arrangement_buffer = malloc(ARRANGEMENT_BUFFER_SIZE);
    d.processor_buffer = malloc(PROCESSOR_BUFFER_SIZE);

    if(!d.stdin_buffer || !d.arrangement_buffer || !d.processor_buffer) {
        fprintf(stderr, "error memory!\n");
        pthread_mutex_destroy(&d.lock);
        free(d.stdin_buffer);
        free(d.arrangement_buffer);
        free(d.processor_buffer);
        return 1;
    }

    // 1. Создаем сокет 
    printf("trying to create client socket...\n");
    
    int try = 1;
    while (!isCreated && !isError) {  //>>исправили условие: !isCreated И !isError
        c.client_socket = socket(AF_INET, SOCK_STREAM, 0);    
 
        if (try == 3) {
            printf("count of tries to create client's socket has been exceeded\n");
            free(c.server_ip);
            pthread_mutex_destroy(&d.lock);

            isError = true;
            break;
        }

        if (c.client_socket == -1) {
            printf("socket error, code: -1\ntry: %d\n", try);  //>>добавили \n
            sleep(RECREATE_INTERVAL);
            
            try++;
            continue;
        }

        printf("the socket has been created, received descriptor: %d\n", c.client_socket);
        isCreated = true;
    }

    if (isError) return 1;

    // 2. Настройка адреса сервера
    memset(&server_addr, 0, sizeof(server_addr));      //>>обнуляем структуру
    
    server_addr.sin_family = AF_INET;                //>>IPv4
    server_addr.sin_port = htons(c.port);           //>>порт сервера в сетевом порядке байтов
    
    if (inet_pton(AF_INET, c.server_ip, &server_addr.sin_addr) <= 0) {
        printf("invalid server's IP address\n");
        close(c.client_socket);   //>>закрываем сокет при ошибке IP
        free(c.server_ip);
        //>> УДАЛИЛИ free(c.port) — port это int, а не указатель!
        pthread_mutex_destroy(&d.lock);

        return 1;
    }

    //                  <~ Инициируем подключение ~>                  //
    while (!stop_client) {
        printf("trying connect to server...\n");

        while (!isConnected && !stop_client) {
            if (connect(c.client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                if(stop_client)break;
                printf("failed to connect\nnext try in %d sec\n", RECONNECT_INTERVAL);  //>>добавили \n
                sleep(RECONNECT_INTERVAL);     //>>ждем перед следующей попыткой 
                continue;
            }

            printf("successful connection\n");
            isConnected = true;
        }       

        if(stop_client)break;

        print_chat_history(&d);
        
        // 3. Запускаем два потока 
        c.stop_flag = &stop_client;
        pthread_t receiver, sender;
        
        while(!stop_client) {
            if(pthread_tryjoin_np(receiver, NULL) == 0 && pthread_tryjoin_np(sender, NULL) == 0) {
                break;
            }

            sleep(1);
        }

        if(stop_client)break;
        isConnected = false;

        // 3.1. Для приема данных
        if (pthread_create(&receiver, NULL, &receive_message, (void *)&thread_args_wrapper) != 0) {
            printf("can't start stream for receive data\n");  //>>добавили \n
            close(c.client_socket);
            free(c.server_ip);

            continue;
        }

        // 3.2. Для отправки данных
        if (pthread_create(&sender, NULL, &send_message, (void *)&thread_args_wrapper) != 0) {
            printf("can't start stream for send data\n");  //>>исправили опечатку: send, а не receive
            close(c.client_socket);
            free(c.server_ip);

            continue;
        }
        if(stop_client) {
            close(c.client_socket);
        }

        pthread_join(receiver, NULL);
        pthread_join(sender, NULL);
    }    

    // free(d.stdin_buffer);
    // free(d.arrangement_buffer);
    // free(d.processor_buffer);

    // pthread_mutex_destroy(&d.lock);
    
    return 0;
}