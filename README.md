# Auth service

## Запуск контейнера

```bash
docker-compose up --build
```

## Примеры запросов

```bash
curl --location 'http://localhost:8080/token' \
--header 'Content-Type: application/json' \
--data '{
    "user_id": "123e4567-e89b-12d3-a456-426614174000"
}'
```

```bash
curl --location 'http://localhost:8080/refresh' \
--header 'Content-Type: application/json' \
--data '{
    "access_token": "TOKEN",
    "refresh_token": "TOKEN"
}'
```