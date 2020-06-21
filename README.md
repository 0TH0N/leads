Pet-проект с лидами. Базу можно смотреть через PHPMyAdmin при запущенном докере
по адресу http://localhost:10088/ в dev режиме. Детально вопросы работы в prod режиме 
связанные с порядком деплоя и загрузки секретных данных в .env файл не прорабатывались. 
Для удобства развертывания локально все .env файлы открыты и закоммичены публично.

1 . Запустите докер с приложением
```bash
make start
```
2 . Вход в докер контейнер приложения
```bash
make enter
```
3 . Cоздайте базу (также не забудьте сделать `composer install` в первый раз):
```bash
make install
```
4 . Потестируйте последовательно по файлу `test.http`

5 . В ходе последовательного исполнения ручных тестов вы дойдете до необходимости загрузки фикстур.
 Об этом будет указано в комментарии файла `test.http`. Сделайте их командой (не всегда срабатывает с первого раза):
 ```bash
 make fixtures
 ```
6 . При необходимости сбросьте базу командой:
 ```bash
 make drop
 ```
7 . Остановить докер с приложением можно командой:
 ```bash
 make stop
 ```
