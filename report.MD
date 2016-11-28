# Trabalho Final de Redes

- Daniel Amarante
- Diego Jornada
- Matthias Nunes

---

## Compilação e Execução

Para compilar o programa deve-se utilizar o `Makefile` executando o comando `make`. Para executar o programa, deve ser executar o comando `sudo ./main <interface>`, utilizando a interface de rede a ser observada.

## Implementação

### Sniffer

O primeiro passo da implementação foi criar o sniffer utilizando sockets. No arquivo `bensocket.c`, capturamos os pacotes para inicializar o processamento. Serão utilizados as structs do sistema para representar os headers. Lendo o pacote, o programa identifica se é `UDP` ou `TCP` para decidir o que fazer. Se for `UDP` será chamada a rotina de detectar `DHCP`, se for `TCP` será chamada a rotina de detectar `HTTP`,

### DHCP

No pacote `UDP`, são analisadas as portas para descobrir se o request é de `DHCP` com origem em um cliente. Após isso, verificamos o tipo nos options do request, para descobrir se é `Discover` ou `Request`. Também é lida a option de `hostname` para salvar ele.

Depois de descobrir qual o tipo de request, o pacote é montado manualmente de acordo com o pacote `DHCP Ack` ou `DHCP Offer`. O ip e mac da máquina servidor são pegos dinamicamente na execução do programa.

Após montado o pacote, ele é enviado por socket para a máquina com o `mac address` origem do pacote recebido.

### Monitorador de Pacotes

O mesmo pacote detectado pelo sniffer, se for `TCP`, será enviado para análise do monitorador. O monitorador irá detectar se o pacote é `HTTP` ou `HTTPS` e extrair os dados do `referer`, para conseguir a url acessada. É então gerado o arquivo HTML com os dados de data e hora de acesso (adquiridos no sistema), endereço ip do host(adquirido no header do ip), nome do host (adquirido no `DHCP`) e url (extraido do `referer`).

## Dificuldades Encontradas

Em testes feitos em casa com um roteador caseiro, algumas vezes o roteador foi mais rápido que o programa para responder os `DHCP Requests` do host.

Ao enviar o ip para uma máquina, não é possível saber se a requisição foi um sucesso, devido ao uso de `UDP`, isso dificultou o uso de multiplos ips para atacar diversas máquinas diferentes.

Também houve dificuldade em descobrir a `url` real acessada, foram tentados utilizar o `location` e o  `host`, mas conseguimos mais sucesso com o `referer`.
