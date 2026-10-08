# Scanner de Portas (uso etico)

Scanner de portas TCP em Python, sem dependencias externas, feito para estudo
e auditorias **autorizadas**.

## Uso

```bash
python scanner_portas.py 127.0.0.1                  # portas comuns
python scanner_portas.py 192.168.0.10 -p 1-1024     # intervalo
python scanner_portas.py 192.168.0.10 -p 22,80,443 -o relatorio.json
```

Opcoes: `-t` threads, `--timeout`, `--atraso` (limita a taxa), `--sem-banner`,
`-o` (relatorio JSON), `--autorizado`.

## Principios

- Redes privadas e localhost rodam direto. IPs publicos exigem confirmacao
  explicita de autorizacao.
- Conexao TCP completa e transparente. Sem furtividade e sem evasao de IDS.
- Limite de threads e opcao de atraso para nao sobrecarregar o alvo.
- Relatorio destaca servicos sensiveis (Telnet, FTP, RDP, SMB etc).

## Onde praticar legalmente

Sua propria maquina, VMs (Metasploitable, DVWA), redes de laboratorio e
plataformas como Hack The Box e TryHackMe. O dominio `scanme.nmap.org` e
liberado pelo projeto Nmap para testes leves.

## Aviso

Varrer sistemas sem permissao pode ser crime. O autor nao se responsabiliza
por uso indevido.

PitDev
