#!/usr/bin/env python3
"""
scanner_portas.py - Scanner de portas TCP para auditorias autorizadas.

Autor: Brenno

Faz varredura TCP connect (conexao completa), identifica o servico mais
provavel pela porta e tenta ler um banner simples. Nao usa tecnicas de
evasao, fragmentacao ou varredura furtiva: a ideia e ser uma ferramenta
transparente, de uso etico.

USE APENAS em sistemas seus ou com autorizacao ESCRITA de quem os administra.
"""

import argparse
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Portas comuns que costumam aparecer em auditorias basicas.
PORTAS_COMUNS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017,
]

# Portas que merecem atencao extra no relatorio (servicos sensiveis/legados).
PORTAS_SENSIVEIS = {
    21: "FTP envia credenciais sem criptografia",
    23: "Telnet envia tudo em texto puro",
    135: "RPC do Windows exposto",
    139: "NetBIOS exposto",
    445: "SMB exposto (verifique patches)",
    3389: "RDP exposto (prefira VPN e MFA)",
    5900: "VNC exposto",
    6379: "Redis costuma rodar sem autenticacao",
    27017: "MongoDB exposto (verifique autenticacao)",
}

AVISO = """
================================ AVISO LEGAL ================================
Varrer sistemas sem permissao pode ser crime (no Brasil, ver Lei 12.737/2012
e Lei 14.155/2021). Use somente em maquinas suas, em laboratorios proprios
ou com autorizacao escrita do responsavel pelo alvo.
=============================================================================
"""


def resolver_alvo(alvo):
    """Converte nome ou IP em um endereco IP. Encerra se nao resolver."""
    try:
        return socket.gethostbyname(alvo)
    except socket.gaierror:
        sys.exit(f"[erro] nao foi possivel resolver o alvo: {alvo}")


def alvo_e_local(ip):
    """True se o IP for de rede privada ou loopback (ambiente de laboratorio)."""
    endereco = ipaddress.ip_address(ip)
    return endereco.is_private or endereco.is_loopback


def confirmar_autorizacao(ip, flag_autorizado):
    """
    Alvos em redes privadas passam direto. Para qualquer IP publico, o
    usuario precisa declarar de forma explicita que tem autorizacao.
    """
    if alvo_e_local(ip):
        return
    print(AVISO)
    if flag_autorizado:
        print(f"[!] Alvo publico ({ip}). Autorizacao declarada via --autorizado.\n")
        return
    resposta = input(f"{ip} e um IP publico. Voce tem autorizacao escrita para varre-lo? (digite SIM): ")
    if resposta.strip().upper() != "SIM":
        sys.exit("[abortado] sem autorizacao confirmada.")


def interpretar_portas(texto):
    """Aceita '80', '20-25', '22,80,443' ou combinacoes como '22,80,8000-8100'."""
    portas = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fim = parte.split("-", 1)
            portas.update(range(int(inicio), int(fim) + 1))
        elif parte:
            portas.add(int(parte))
    invalidas = [p for p in portas if not 1 <= p <= 65535]
    if invalidas:
        raise ValueError(f"portas fora do intervalo 1-65535: {invalidas[:5]}")
    return sorted(portas)


def nome_servico(porta):
    try:
        return socket.getservbyport(porta, "tcp")
    except OSError:
        return "desconhecido"


def pegar_banner(ip, porta, timeout):
    """Tenta ler uma linha de identificacao do servico, sem enviar payloads agressivos."""
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            s.settimeout(timeout)
            if porta in (80, 8000, 8080, 8443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            dados = s.recv(256)
            return dados.decode(errors="ignore").strip().splitlines()[0][:120] if dados else ""
    except (OSError, IndexError):
        return ""


def testar_porta(ip, porta, timeout, banner):
    """Tenta uma conexao TCP completa. Retorna dict se a porta estiver aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, porta)) != 0:
                return None
    except OSError:
        return None
    return {
        "porta": porta,
        "servico": nome_servico(porta),
        "banner": pegar_banner(ip, porta, timeout) if banner else "",
        "alerta": PORTAS_SENSIVEIS.get(porta, ""),
    }


def varrer(ip, portas, threads, timeout, banner, atraso):
    abertas = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futuros = []
        for porta in portas:
            futuros.append(pool.submit(testar_porta, ip, porta, timeout, banner))
            if atraso:
                time.sleep(atraso)  # limita a taxa para nao sobrecarregar o alvo
        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado:
                abertas.append(resultado)
    return sorted(abertas, key=lambda r: r["porta"])


def mostrar(abertas):
    if not abertas:
        print("Nenhuma porta aberta encontrada no intervalo testado.")
        return
    print(f"\n{'PORTA':<8}{'SERVICO':<16}BANNER")
    print("-" * 60)
    for r in abertas:
        print(f"{r['porta']:<8}{r['servico']:<16}{r['banner']}")
    alertas = [r for r in abertas if r["alerta"]]
    if alertas:
        print("\nPontos de atencao:")
        for r in alertas:
            print(f"  - {r['porta']}/tcp: {r['alerta']}")


def salvar_relatorio(caminho, alvo, ip, portas, abertas, inicio, fim):
    relatorio = {
        "alvo": alvo,
        "ip": ip,
        "inicio": inicio.isoformat(timespec="seconds"),
        "duracao_s": round((fim - inicio).total_seconds(), 2),
        "portas_testadas": len(portas),
        "portas_abertas": abertas,
    }
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=2)
    print(f"\nRelatorio salvo em {caminho}")


def criar_parser():
    p = argparse.ArgumentParser(
        description="Scanner de portas TCP para auditorias autorizadas.",
        epilog="Exemplo: python scanner_portas.py 127.0.0.1 -p 1-1024",
    )
    p.add_argument("alvo", help="IP ou hostname")
    p.add_argument("-p", "--portas", help="ex: 80 | 20-25 | 22,80,443 (padrao: portas comuns)")
    p.add_argument("-t", "--threads", type=int, default=50, help="conexoes simultaneas (padrao: 50)")
    p.add_argument("--timeout", type=float, default=1.0, help="segundos por conexao (padrao: 1.0)")
    p.add_argument("--atraso", type=float, default=0.0, help="pausa entre tentativas, em segundos")
    p.add_argument("--sem-banner", action="store_true", help="nao tenta ler banners")
    p.add_argument("-o", "--saida", help="salva o relatorio em JSON neste arquivo")
    p.add_argument("--autorizado", action="store_true",
                   help="declara que voce tem autorizacao para varrer um IP publico")
    return p


def main():
    args = criar_parser().parse_args()

    try:
        portas = interpretar_portas(args.portas) if args.portas else PORTAS_COMUNS
    except ValueError as erro:
        sys.exit(f"[erro] {erro}")

    ip = resolver_alvo(args.alvo)
    confirmar_autorizacao(ip, args.autorizado)

    threads = max(1, min(args.threads, 200))  # teto de seguranca
    print(f"Alvo: {args.alvo} ({ip}) | portas: {len(portas)} | threads: {threads}")

    inicio = datetime.now()
    try:
        abertas = varrer(ip, portas, threads, args.timeout, not args.sem_banner, args.atraso)
    except KeyboardInterrupt:
        sys.exit("\n[interrompido] varredura cancelada pelo usuario.")
    fim = datetime.now()

    mostrar(abertas)
    print(f"\nConcluido em {(fim - inicio).total_seconds():.2f}s")
    if args.saida:
        salvar_relatorio(args.saida, args.alvo, ip, portas, abertas, inicio, fim)


if __name__ == "__main__":
    main()
