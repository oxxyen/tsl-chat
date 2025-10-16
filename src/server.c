#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

// Заголовки проекта
#include "../headers/config.h"      // содержит PORT, IP, HISTORY_MAX_SIZE и др.
#include "../headers/client-data.h" // содержит структуру data и функции работы с историей

// Настройки сервера
#define MAX_CLIENTS 10              // Максимальное число подключённых клиентов
#define BUFFER_SIZE 256             // Размер буфера для приёма сообщения

// Глобальные переменные чата
data chat_data = {0};               // Хранит историю сообщений и мьютекс
int client_sockets[MAX_CLIENTS] = {0}; // Массив сокетов подключённых клиентов
int client_count = 0;               // Текущее число клиентов
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER; // Защита списка клиентов

/**
 * Рассылает сообщение всем подключённым клиентам, кроме отправителя.
 * Также добавляет сообщение в общую историю чата.
 * 
 * @param msg Указатель на строку с сообщением (должна быть завершена нулём).
 * @param sender_fd Дескриптор сокета отправителя (чтобы не отправлять ему же).
 */
void broadcast_message(const char *msg, int sender_fd) {
    // Защищаем доступ к списку клиентов
    pthread_mutex_lock(&client_mutex);
    for (int i = 0; i < client_count; i++) {
        if (client_sockets[i] != 0 && client_sockets[i] != sender_fd) {
            // Отправляем сообщение + символ новой строки для читаемости
            send(client_sockets[i], msg, strlen(msg), 0);
            send(client_sockets[i], "\n", 1, 0);
        }
    }
    pthread_mutex_unlock(&client_mutex);

    // Добавляем сообщение в историю (с защитой мьютексом из chat_data)
    pthread_mutex_lock(&chat_data.lock);
    add_message_to_history(&chat_data, msg);
    pthread_mutex_unlock(&chat_data.lock);
}

/**
 * Поток обработки одного клиента.
 * Принимает сообщения, рассылает их, отправляет историю при подключении.
 * 
 * @param arg Указатель на int — дескриптор сокета клиента.
 * @return NULL (всегда)
 */
void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg); // Освобождаем память, выделенную под аргумент

    printf("Новый клиент подключился. Сокет: %d\n", client_fd);

    // Отправляем всю историю чата новому клиенту
    pthread_mutex_lock(&chat_data.lock);
    for (int i = 0; i < chat_data.count_of_messages; i++) {
        if (chat_data.chat_history[i] != NULL) {
            send(client_fd, chat_data.chat_history[i], strlen(chat_data.chat_history[i]), 0);
            send(client_fd, "\n", 1, 0); // Каждое сообщение на новой строке
        }
    }
    pthread_mutex_unlock(&chat_data.lock);

    char buffer[BUFFER_SIZE];
    char full_msg[BUFFER_SIZE + 32]; // Буфер для формирования "Client: ..."

    // Основной цикл приёма сообщений
    while (1) {
        ssize_t bytes = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) {
            // Клиент отключился или ошибка соединения
            printf("Клиент отключился. Сокет: %d\n", client_fd);
            break;
        }

        // Завершаем строку и удаляем символы перевода строки
        buffer[bytes] = '\0';
        buffer[strcspn(buffer, "\n\r")] = '\0';

        // Проверяем команду выхода
        if (strcmp(buffer, "/quit") == 0) {
            printf("Клиент запросил отключение. Сокет: %d\n", client_fd);
            break;
        }

        // Формируем сообщение для рассылки
        snprintf(full_msg, sizeof(full_msg), "Client: %s", buffer);
        printf("Получено сообщение: %s\n", full_msg);

        // Рассылаем всем остальным
        broadcast_message(full_msg, client_fd);
    }

    // Удаляем клиента из списка
    pthread_mutex_lock(&client_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] == client_fd) {
            client_sockets[i] = 0; // Освобождаем слот
            client_count--;        // Уменьшаем счётчик
            break;
        }
    }
    pthread_mutex_unlock(&client_mutex);

    // Закрываем сокет
    close(client_fd);
    return NULL;
}

/**
 * Точка входа сервера.
 * Инициализирует сокет, запускает прослушивание порта,
 * создаёт поток для каждого нового клиента.
 */
int main(void) {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Инициализируем мьютекс для защиты истории чата
    pthread_mutex_init(&chat_data.lock, NULL);

    // Создаём TCP-сокет
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Ошибка создания сокета");
        exit(EXIT_FAILURE);
    }

    // Разрешаем повторное использование адреса (чтобы не ждать TIME_WAIT)
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Настраиваем адрес сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Слушать все интерфейсы
    server_addr.sin_port = htons(PORT);       // Порт из config.h

    // Привязываем сокет к адресу
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Ошибка привязки сокета");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Начинаем прослушивание
    if (listen(server_fd, 5) == -1) {
        perror("Ошибка прослушивания");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("✅ Сервер запущен и слушает %s:%d\n", IP, PORT);

    // Основной цикл приёма подключений
    while (1) {
        // Принимаем новое подключение
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (*client_fd == -1) {
            perror("Ошибка accept");
            free(client_fd);
            continue; // Не завершать сервер из-за одной ошибки
        }

        // Проверяем лимит клиентов
        pthread_mutex_lock(&client_mutex);
        if (client_count >= MAX_CLIENTS) {
            pthread_mutex_unlock(&client_mutex);
            printf("❌ Достигнут лимит клиентов (%d). Подключение отклонено.\n", MAX_CLIENTS);
            close(*client_fd);
            free(client_fd);
            continue;
        }

        // Добавляем клиента в список
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] == 0) {
                client_sockets[i] = *client_fd;
                client_count++;
                break;
            }
        }
        pthread_mutex_unlock(&client_mutex);

        // Создаём поток для обработки клиента
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, client_fd) != 0) {
            perror("Ошибка создания потока");
            close(*client_fd);
            free(client_fd);
            continue;
        }
        pthread_detach(tid); // Поток сам освободит ресурсы после завершения
    }

    // Эта часть никогда не выполнится (бесконечный цикл выше),
    // но оставим для аккуратности
    pthread_mutex_destroy(&chat_data.lock);
    close(server_fd);
    return 0;
}