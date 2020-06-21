start:
	docker-compose up -d

enter:
	docker exec -it leads_app bash

stop:
	docker-compose down

install:
	bin/console doctrine:database:create
	bin/console doctrine:migrations:migrate

drop:
	bin/console doctrine:database:drop --force

fixtures:
	bin/console doctrine:fixtures:load