#!/bin/bash
set -e

mkdir -p bin

# Сборка всех модулей
gcc -c src/client-data.c -o bin/client-data.o -Iheaders
gcc -c src/sanitizer.c -o bin/sanitizer.o -Iheaders
gcc -c src/receive-message.c -o bin/receive-message.o -Iheaders
gcc -c src/send-message.c -o bin/send-message.o -Iheaders
gcc -c src/command-type.c -o bin/command-type.o -Iheaders

# Сборка клиента и сервера
gcc bin/*.o src/client.c -o bin/client -Iheaders -lpthread
gcc bin/*.o src/server.c -o bin/server -Iheaders -lpthread

echo "✅ Сборка завершена: bin/client, bin/server"