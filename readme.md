C CODE SECURITY ANALYSIS REPORT
================================

Scanned files: 23
Issues found: 149

FILE: ./src/command-type.c
LINE 22:     *    Делим одно на другое, чтобы получить количество элементов          *
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/receive-message.c
LINE 9:  *    buffer: указатель на массив байтов, откуда распаковываем                       *
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/receive-message.c
LINE 10:  *    offset: указатель на текущее смещение в битах (обновляется после распаковки)   *
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/receive-message.c
LINE 49:     ssize_t bytes_received;    //>>присвоим полученный размер пакета байт (можно int, но лучше ssize_t на случай, если размер превысит размер int)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/receive-message.c
LINE 79:         d -> chat_history[0] = malloc(message_size + CONTROL_CHARACTERS);
ERROR: Memory Allocation Error
DESCRIPTION: malloc() without NULL check
SUGGESTION: Always check malloc return value: if(ptr == NULL) { error_handling }
----------------------------------------
FILE: ./src/receive-message.c
LINE 82:         memcpy(d -> chat_history[d -> count_of_messages], &d->processor_buffer[HEADER], message_size);    //>>после очистки d -> count_of_messages = 0!
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/receive-message.c
LINE 86:         /*логика полученного метода, в данной реализации у нас всегда SEND*/
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/receive-message.c
LINE 90:         d -> chat_history[count_of_messages - 1] = malloc(message_size + CONTROL_CHARACTERS);
ERROR: Memory Allocation Error
DESCRIPTION: malloc() without NULL check
SUGGESTION: Always check malloc return value: if(ptr == NULL) { error_handling }
----------------------------------------
FILE: ./src/sanitizer.c
LINE 3: #include <stdbool.h>                        //>>использование типа boolean (true/false за место 1/0)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/sanitizer.c
LINE 16:     d -> stdin_buffer[MAX_MSG_LEN];                      // <~ БУФЕР ДЛЯ ВВЕДЕННОГО СООБЩЕНИЯ (1000 символов)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/sanitizer.c
LINE 17:     d -> arrangement_buffer[ARRANGEMENT_BUFFER_SIZE];   // <~ БУФЕР ДЛЯ ФОРМИРОВАНИЯ ПАКЕТА (1000 + ЗАРЕЗЕРВИРОВАННЫЕ ПОД ПАРАМЕТРЫ)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/sanitizer.c
LINE 22:         if (fgets(d -> stdin_buffer, (sizeof(d -> stdin_buffer)), stdin)== NULL) {
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'gets(' detected
SUGGESTION: Replace with safe alternative: fgets()
----------------------------------------
FILE: ./src/sanitizer.c
LINE 69:             d -> chat_history[d -> count_of_messages] = malloc(current_len + 1);
ERROR: Memory Allocation Error
DESCRIPTION: malloc() without NULL check
SUGGESTION: Always check malloc return value: if(ptr == NULL) { error_handling }
----------------------------------------
FILE: ./src/sanitizer.c
LINE 78:             strcpy(d -> chat_history[d -> count_of_messages], d -> stdin_buffer);
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./src/send-message.c
LINE 2: #include <stdbool.h>                        //>>использование типа boolean (true/false за место 1/0)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/send-message.c
LINE 12:  *    Устанавливаем соответствующий бит в буфере по текущему смещению            *
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/send-message.c
LINE 14:  *    (1 << (*bit % 8)) - это маска для установки нужного бита в этом байте   *
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/send-message.c
LINE 63:     if (d -> count_of_messages == HISTORY_MAX_SIZE) isOverflow = true;  // !чистим историю в is_valid_input(), тут выставляем флаг
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 18: #include "../headers/client-data.h" // содержит структуру data и функции работы с историей
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 42:  * Рассылает сообщение всем подclient_thread_data_tключённым клиентам, кроме отправителя.
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 45:  * @param msg Указатель на строку с сообщением (должна быть завершена нулём).
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 46:  * @param sender_fd Дескриптор сокета отправителя (чтобы не отправлять ему же).
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 76:  * Принимает сообщения, рассылает их, отправляет историю при подключении.
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 83:     free(arg); // Освобождаем память, выделенную под аргумент
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/server.c
LINE 127:             if(mr_encrypt(session, MR_MSG_TYPE_TEXT, (uint8_t*)chat_data.chat_history[i], strlen(chat_data.chat_history[i]), hist_ct, sizeof(hist_ct), &hist_ct_len) == MR_SUCCESS) {
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/server.c
LINE 171:             printf("client %d changedd nick on: %s\n", client_fd, new_nick);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./src/server.c
LINE 188:         snprintf(full_msg, sizeof(full_msg), "%s: %s", display_name, plaintext);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./src/server.c
LINE 190:         printf("get: %s\n", full_msg);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./src/server.c
LINE 199:             mr_session_free(clients[i].session);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/server.c
LINE 271:     printf("✅ Сервер запущен и слушает %s:%d\n", IP, PORT);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./src/server.c
LINE 279:         int* pclient_fd = malloc(sizeof(int));
ERROR: Memory Allocation Error
DESCRIPTION: malloc() without NULL check
SUGGESTION: Always check malloc return value: if(ptr == NULL) { error_handling }
----------------------------------------
FILE: ./src/server.c
LINE 282:         if(*pclient_fd == -1) {perror("error accept!"); free(pclient_fd); continue;}
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/server.c
LINE 288:             free(pclient_fd);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/server.c
LINE 297:             free(pclient_fd);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/crypto.c
LINE 22: int encrypt_message(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext) {
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/crypto.c
LINE 33:     EVP_CIPHER_CTX_free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/crypto.c
LINE 36:     EVP_CIPHER_CTX_free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/crypto.c
LINE 51:     EVP_CIPHER_CTX_free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/crypto.c
LINE 54:     EVP_CIPHER_CTX_free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client.c
LINE 45:     c.client_socket = SOCKET;        //>>перед созданием сокета присваиваем константное значение (чтобы не хранить мусор)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client.c
LINE 49:     thread_args_wrapper.c = &c;    //>>для потоков нам необходимо передавать 1 структуру
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client.c
LINE 50:     thread_args_wrapper.d = &d;   //   поэтому будем хранить 2 указателя на нужные нам структуры в отдельной 
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client.c
LINE 53:     bool isConnected = false;     //>>флаг подключения (пока true = есть активное подключение)
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client.c
LINE 76:             free(c.server_ip);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client.c
LINE 101:     server_addr.sin_port = htons(c.port);           //>>порт сервера в сетевом порядке байтов
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client.c
LINE 106:         free(c.server_ip);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client.c
LINE 173:             free(c.server_ip);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client.c
LINE 180:             printf("can't start stream for send data\n");  //>>исправили опечатку: send, а не receive
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client.c
LINE 182:             free(c.server_ip);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client.c
LINE 193:     if (c.session) mr_session_free(c.session);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client.c
LINE 197:     free(c.server_ip);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./src/client-data.c
LINE 5: #include "../headers/client-data.h"  // Здесь объявлена структура data и прототипы функций
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client-data.c
LINE 23:             printf("%s\n", d->chat_history[i]);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./src/client-data.c
LINE 38:  * @param msg Указатель на строку сообщения (должна быть завершена нулём).
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./src/client-data.c
LINE 48:         char *copy = malloc(strlen(msg) + 1);
ERROR: Memory Allocation Error
DESCRIPTION: malloc() without NULL check
SUGGESTION: Always check malloc return value: if(ptr == NULL) { error_handling }
----------------------------------------
FILE: ./src/client-data.c
LINE 51:             strcpy(copy, msg);
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./mesh_protocol/utils/replay_protection.c
LINE 11:         free(cache);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/utils/replay_protection.c
LINE 79:         free(cache->entries);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/session/storage.c
LINE 161:         free(session);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/session/storage.c
LINE 170:         free(session);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/session/storage.c
LINE 198:             free(session->replay_cache);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/crypto/crypto.c
LINE 39:         if(ctx->encrypt_ctx) EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/crypto/crypto.c
LINE 40:         if(ctx->decrypt_ctx) EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 33: int mr_session_create_advanced(mr_ctx_t* ctx, const mr_key_pair_t* local_key, const uint8_t* remote_public_key, size_t pubkey_len, mr_mode_t mode, mr_session_t** session);
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 88:     EVP_KDF_free(kdf);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 111:     EVP_KDF_CTX_free(kctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 122:         if (local) EVP_PKEY_free(local);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 123:         if (remote) EVP_PKEY_free(remote);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 130:         EVP_PKEY_CTX_free(dh_ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 131:         EVP_PKEY_free(local);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 132:         EVP_PKEY_free(remote);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 139:     EVP_PKEY_CTX_free(dh_ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 140:     EVP_PKEY_free(local);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 141:     EVP_PKEY_free(remote);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 146: static void ratchet_chain_key(uint8_t chain_key[MR_CHAIN_KEY_LEN], uint8_t output_key[MR_CHAIN_KEY_LEN], mr_mode_t mode) {
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 248:     EVP_CIPHER_CTX_free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 299:     EVP_CIPHER_CTX_free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 356:         free(ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 371:         free(key_pair);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 379:         free(key_pair);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 385:         EVP_PKEY_free(pkey);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 387:         free(key_pair);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 391:     EVP_PKEY_free(pkey);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 410:         free(key_pair);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 430:         free(key_pair);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 434: int mr_session_create(mr_ctx_t* ctx, const mr_key_pair_t* local_key, const uint8_t* remote_public_key, size_t pubkey_len, mr_session_t** session) {
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 597:             free(sess->replay_cache);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 601:         free(sess);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 818:             if(EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) == 1 && EVP_DigestUpdate(md_ctx, ciphertext, ct_len) == 1 && EVP_DigestFinal_ex(md_ctx, message_hash, NULL) == 1) {
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 820:                     EVP_MD_CTX_free(md_ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 825:             EVP_MD_CTX_free(md_ctx);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 985: void mr_session_free(mr_session_t* session) {
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 1004:             free(current->data);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 1005:             free(current);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/meshratchet.c
LINE 1013:         free(session);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/multicast.c
LINE 26:         free(group);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/multicast.c
LINE 61: void mr_multicast_group_free(mr_multicast_group_t* group) {
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/multicast.c
LINE 66:         free(group->peers);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./mesh_protocol/src/multicast.c
LINE 70:         free(group);
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./scanner.c
LINE 44:         snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 70:         "gets(", "strcpy(", "strcat(", "sprintf(", "scanf(", "vsprintf("
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'gets(' detected
SUGGESTION: Replace with safe alternative: fgets()
----------------------------------------
FILE: ./scanner.c
LINE 70:         "gets(", "strcpy(", "strcat(", "sprintf(", "scanf(", "vsprintf("
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 70:         "gets(", "strcpy(", "strcat(", "sprintf(", "scanf(", "vsprintf("
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcat(' detected
SUGGESTION: Replace with safe alternative: strncat()
----------------------------------------
FILE: ./scanner.c
LINE 70:         "gets(", "strcpy(", "strcat(", "sprintf(", "scanf(", "vsprintf("
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'sprintf(' detected
SUGGESTION: Replace with safe alternative: snprintf()
----------------------------------------
FILE: ./scanner.c
LINE 70:         "gets(", "strcpy(", "strcat(", "sprintf(", "scanf(", "vsprintf("
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'scanf(' detected
SUGGESTION: Replace with safe alternative: fgets()+sscanf()
----------------------------------------
FILE: ./scanner.c
LINE 70:         "gets(", "strcpy(", "strcat(", "sprintf(", "scanf(", "vsprintf("
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'vsprintf(' detected
SUGGESTION: Replace with safe alternative: vsnprintf()
----------------------------------------
FILE: ./scanner.c
LINE 74:         "fgets()", "strncpy()", "strncat()", "snprintf()", "fgets()+sscanf()", "vsnprintf()"
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'gets(' detected
SUGGESTION: Replace with safe alternative: fgets()
----------------------------------------
FILE: ./scanner.c
LINE 74:         "fgets()", "strncpy()", "strncat()", "snprintf()", "fgets()+sscanf()", "vsnprintf()"
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'scanf(' detected
SUGGESTION: Replace with safe alternative: fgets()+sscanf()
----------------------------------------
FILE: ./scanner.c
LINE 80:             strcpy(reports[report_count].error_type, "Buffer Overflow Risk");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 96:         strcpy(reports[report_count].error_type, "Memory Allocation Error");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 97:         strcpy(reports[report_count].description, "malloc() without NULL check");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 98:         strcpy(reports[report_count].suggestion, "Always check malloc return value: if(ptr == NULL) { error_handling }");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 98:         strcpy(reports[report_count].suggestion, "Always check malloc return value: if(ptr == NULL) { error_handling }");
ERROR: Code Style Issue
DESCRIPTION: Line too long (hard to read)
SUGGESTION: Break long lines into multiple lines (< 80-120 chars)
----------------------------------------
FILE: ./scanner.c
LINE 107:         strcpy(reports[report_count].error_type, "Memory Management");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 108:         strcpy(reports[report_count].description, "free() without NULL check");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 109:         strcpy(reports[report_count].suggestion, "Check pointer before free: if(ptr) free(ptr);");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 109:         strcpy(reports[report_count].suggestion, "Check pointer before free: if(ptr) free(ptr);");
ERROR: Memory Management
DESCRIPTION: free() without NULL check
SUGGESTION: Check pointer before free: if(ptr) free(ptr);
----------------------------------------
FILE: ./scanner.c
LINE 119:         strcpy(reports[report_count].error_type, "Format String Vulnerability");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 120:         strcpy(reports[report_count].description, "Unbounded string format specifier");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 121:         strcpy(reports[report_count].suggestion, "Use length-limited specifier: %.*s with length parameter");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 129:     if (strstr(line, "atoi(")) {
ERROR: Integer Handling Issue
DESCRIPTION: atoi() doesn't detect errors
SUGGESTION: Use strtol() with error checking instead
----------------------------------------
FILE: ./scanner.c
LINE 131:         strcpy(reports[report_count].error_type, "Integer Handling Issue");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 132:         strcpy(reports[report_count].description, "atoi() doesn't detect errors");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 132:         strcpy(reports[report_count].description, "atoi() doesn't detect errors");
ERROR: Integer Handling Issue
DESCRIPTION: atoi() doesn't detect errors
SUGGESTION: Use strtol() with error checking instead
----------------------------------------
FILE: ./scanner.c
LINE 133:         strcpy(reports[report_count].suggestion, "Use strtol() with error checking instead");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 141:     if (strstr(line, "system(") || strstr(line, "popen(") || strstr(line, "exec(")) {
ERROR: Command Injection Risk
DESCRIPTION: Dangerous system command execution
SUGGESTION: Validate and sanitize all input, use full path for commands
----------------------------------------
FILE: ./scanner.c
LINE 143:         strcpy(reports[report_count].error_type, "Command Injection Risk");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 144:         strcpy(reports[report_count].description, "Dangerous system command execution");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 145:         strcpy(reports[report_count].suggestion, "Validate and sanitize all input, use full path for commands");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 154:     if (strstr(line, " = 1024;") || strstr(line, " = 256;") || strstr(line, " = 512;") ||
ERROR: Code Quality Issue
DESCRIPTION: Magic number used instead of named constant
SUGGESTION: Define constants with meaningful names: #define BUFFER_SIZE 1024
----------------------------------------
FILE: ./scanner.c
LINE 155:         strstr(line, " = 2048;") || strstr(line, " = 4096;")) {
ERROR: Code Quality Issue
DESCRIPTION: Magic number used instead of named constant
SUGGESTION: Define constants with meaningful names: #define BUFFER_SIZE 1024
----------------------------------------
FILE: ./scanner.c
LINE 157:         strcpy(reports[report_count].error_type, "Code Quality Issue");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 158:         strcpy(reports[report_count].description, "Magic number used instead of named constant");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 159:         strcpy(reports[report_count].suggestion, "Define constants with meaningful names: #define BUFFER_SIZE 1024");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 168:         strcpy(reports[report_count].error_type, "Code Style Issue");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 169:         strcpy(reports[report_count].description, "Line too long (hard to read)");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 170:         strcpy(reports[report_count].suggestion, "Break long lines into multiple lines (< 80-120 chars)");
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'strcpy(' detected
SUGGESTION: Replace with safe alternative: strncpy()
----------------------------------------
FILE: ./scanner.c
LINE 187:     while (fgets(line, sizeof(line), file) && report_count < MAX_ERRORS - 1) {
ERROR: Buffer Overflow Risk
DESCRIPTION: Dangerous function 'gets(' detected
SUGGESTION: Replace with safe alternative: fgets()
----------------------------------------
FILE: ./scanner.c
LINE 231:         fprintf(report, "FILE: %s\n", reports[i].filename);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 232:         fprintf(report, "LINE %d: %s", reports[i].line_number, reports[i].line_content);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 233:         fprintf(report, "ERROR: %s\n", reports[i].error_type);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 234:         fprintf(report, "DESCRIPTION: %s\n", reports[i].description);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 235:         fprintf(report, "SUGGESTION: %s\n", reports[i].suggestion);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 236:         fprintf(report, "%s\n", "----------------------------------------");
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 246:         printf("Usage: %s <directory_to_scan> <report_file>\n", argv[0]);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 247:         printf("Example: %s ./src security_report.txt\n");
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 252:     printf("Scanning directory: %s\n", argv[1]);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 263:         printf("Analyzing: %s\n", c_files.files[i]);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
FILE: ./scanner.c
LINE 269:     printf("Analysis complete. Report saved to: %s\n", argv[2]);
ERROR: Format String Vulnerability
DESCRIPTION: Unbounded string format specifier
SUGGESTION: Use length-limited specifier: %.*s with length parameter
----------------------------------------
