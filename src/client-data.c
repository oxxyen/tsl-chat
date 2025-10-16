#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../headers/client-data.h"  // Здесь объявлена структура data и прототипы функций

/**
 * Выводит всю историю чата на экран.
 * 
 * Функция защищает доступ к данным с помощью мьютекса,
 * чтобы избежать гонки при одновременном чтении/записи.
 * 
 * @param d Указатель на структуру данных чата.
 */
void print_chat_history(data *d) {
    if (!d) return; // Защита от NULL-указателя

    pthread_mutex_lock(&d->lock); // Блокируем доступ к данным

    printf("\n----- ИСТОРИЯ ЧАТА -----\n");
    for (int i = 0; i < d->count_of_messages; i++) {
        if (d->chat_history[i]) { // Проверяем, что сообщение не NULL
            printf("%s\n", d->chat_history[i]);
        }
    }
    printf("------------------------\n");

    pthread_mutex_unlock(&d->lock); // Разблокируем доступ
}

/**
 * Добавляет новое сообщение в историю чата.
 * 
 * Выделяет память под копию сообщения, сохраняет её в массиве.
 * Если история заполнена — игнорирует новое сообщение.
 * 
 * @param d Указатель на структуру данных чата.
 * @param msg Указатель на строку сообщения (должна быть завершена нулём).
 */
void add_message_to_history(data *d, const char *msg) {
    if (!d || !msg) return; // Защита от некорректных аргументов

    pthread_mutex_lock(&d->lock); // Блокируем доступ к данным

    // Проверяем, есть ли место в истории
    if (d->count_of_messages < HISTORY_MAX_SIZE) {
        // Выделяем память под копию строки
        char *copy = malloc(strlen(msg) + 1);
        if (copy) {
            // Копируем сообщение
            strcpy(copy, msg);
            // Сохраняем указатель в массив
            d->chat_history[d->count_of_messages] = copy;
            // Увеличиваем счётчик
            d->count_of_messages++;
        }
        // Если malloc вернул NULL — игнорируем (не хватило памяти)
    }

    pthread_mutex_unlock(&d->lock); // Разблокируем доступ
}