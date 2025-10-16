#include <stdio.h>                            //>>стандартный ввод/вывод (printf, fgets)
#include <stdlib.h>                          //>>выделение памяти (malloc, free)
#include <stdbool.h>                        //>>использование типа boolean (true/false за место 1/0)
#include <string.h>                        //>>работа со строками (strlen)

#include "../headers/config.h"
#include "../headers/client-data.h"

// ОЧИЩАЕМ ЧАТ, ЕСЛИ ПОЛУЧИЛИ ФЛАГ ПЕРЕПОЛНЕНИЯ 
void clear_chat_history(data *d) {
    for (int i = 0; i < d -> count_of_messages; i++) {
        free(d -> chat_history[i]);  //>>освобождаем структуру
        d->chat_history[i] = NULL;  //>>сбрасываем указатель 
    }

    for (int i = 0; i < d -> count_of_messages; i++) {
        d->message_size[i] = 0;
    }

    d -> count_of_messages = 0;
    printf("history of the chat were reset\n");

    return;
}

// // ВЫВОДИМ ИСТОРИЮ СООБЩЕНИЙ
// void print_chat_history(data *d) {
//     /*лок*/ pthread_mutex_lock(&d -> lock); 
   
//     system("clear");

//     for (int i = 0; i < d -> count_of_messages; i++) {
//         printf("%s", d -> chat_history[i]);
//     }
    
//     printf("\n\nenter message: "); 
    
//     /*анлок*/ pthread_mutex_unlock(&d -> lock);
// }

// ПРОВЕРЯЕМ ВВОД ПОЛЬЗОВАТЕЛЯ НА ВАЛИДНОСТЬ ПЕРЕД ОТПРАВКОЙ 
bool is_valid_input(data *d) {    
    bool isValid_message = false;    //>>флаг валидного сообщения 
    bool isError = false;           //>>флаг ошибки

    int try = 1;                  //>>счетчик 

    d -> stdin_buffer[MAX_MSG_LEN];                      // <~ БУФЕР ДЛЯ ВВЕДЕННОГО СООБЩЕНИЯ (1000 символов)
    d -> arrangement_buffer[ARRANGEMENT_BUFFER_SIZE];   // <~ БУФЕР ДЛЯ ФОРМИРОВАНИЯ ПАКЕТА (1000 + ЗАРЕЗЕРВИРОВАННЫЕ ПОД ПАРАМЕТРЫ)
    
    // 1. Обрабатываем пользовательский ввод с stdin 
    while (!isValid_message && !isError) {
        // !1.1. Если ошибка ф-ии fgets - падаем с ошибкой
        if (fgets(d -> stdin_buffer, (sizeof(d -> stdin_buffer)), stdin)== NULL) {
            printf("fgets error");
            
            isError = true;
            break;
        }

        int current_len = strlen(d -> stdin_buffer);

        // !1.2. Если длина сообщения больше 1000 символов (с учетом переноса строки), перезапускаем цикл 
        if (current_len == (MAX_MSG_LEN - 1) && d -> stdin_buffer[current_len - 1] != '\n') {
            printf("input message is bigger then 1000 symbols\ntry again:");
            
            int c; 
            while ((c = getchar()) != '\n' && c != EOF);

            continue;
        }
        
        // !1.3. Если строка пустая, перезапускаем цикл 
        if (current_len == 0) {
            printf("you can't send empty message\ntry again:");
            
            continue;
        }

        // ~1.4. Присваиваем нулевой терминатор за место переноса строки 
        if (current_len > 0 && d -> stdin_buffer[current_len - 1] == '\n') {
            d -> stdin_buffer[strlen(d -> stdin_buffer) - 1] = '\0';
        }

        // 2. Пробуем выделить память под сообщение и перенести его в историю
        while (1) {
            // !2.1. Если попыток больше 3, падаем с ошибкой (аномальное поведение)
            if (try > 3) {
                printf("tries of malloc ran out\ntry out to reload messanger");    

                isError = true;
                break;
            }

            // ~2.2. Сперва проверяем на переполнение
            if (d -> count_of_messages == HISTORY_MAX_SIZE) {
                clear_chat_history(d);
            }

            // !2.3. Выделяем память по указателю, если ошибка, перезапускаем цикл
            d -> chat_history[d -> count_of_messages] = malloc(current_len + 1);
            if (d -> chat_history[d -> count_of_messages] == NULL) {
                printf("malloc error\nentered message did not sended\ntry to malloc again...");
                
                try++;
                continue;
            }

            // 3. Копируем строку в историю 
            strcpy(d -> chat_history[d -> count_of_messages], d -> stdin_buffer);
            d -> message_size[d -> count_of_messages] = strlen(d -> stdin_buffer) + CONTROL_CHARACTERS;
            d -> count_of_messages++;

            break;
        }

        isValid_message = true;
    }

    if (isError || !isValid_message) return false;

    return true;
}

