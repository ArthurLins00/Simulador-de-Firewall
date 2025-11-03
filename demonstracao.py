"""
Script de demonstração do Firewall Simulator
Mostra o firewall em ação permitindo e bloqueando pacotes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.firewall_core import FirewallSimulator
import time

def print_header(text):
    """Imprime um cabeçalho formatado"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def print_packet_test(firewall, src_ip, dst_port, protocol="TCP"):
    """Testa um pacote e mostra o resultado formatado"""
    resultado = firewall.evaluate_packet(src_ip, dst_port, protocol)
    
    status = "[PERMITIDO]" if resultado == "ALLOW" else "[BLOQUEADO]"
    status_symbol = "[OK]" if resultado == "ALLOW" else "[X]"
    
    print(f"\n{status_symbol} Testando pacote:")
    print(f"   Origem: {src_ip}")
    print(f"   Destino: Porta {dst_port} ({protocol})")
    print(f"   Decisão: {status} {resultado}")
    print("-" * 70)

def main():
    print_header("*** FIREWALL SIMULATOR - DEMONSTRACAO ***")
    
    # Criar firewall
    firewall = FirewallSimulator(default_policy="ALLOW")
    
    print("\n[INFO] Carregando regras de firewall...")
    print("   (Arquivo: regras_exemplo.txt)\n")
    
    try:
        firewall.load_rules("regras_exemplo.txt")
    except FileNotFoundError:
        print("[ERRO] Arquivo regras_exemplo.txt não encontrado!")
        print("Criando regras de exemplo...\n")
        # Adicionar regras manualmente se o arquivo não existir
        firewall.add_rule("BLOCK IP 192.168.1.100")
        firewall.add_rule("BLOCK IP 10.0.0.50")
        firewall.add_rule("ALLOW PORT 80")
        firewall.add_rule("ALLOW PORT 443")
        firewall.add_rule("ALLOW PORT 22")
        firewall.add_rule("BLOCK PORT 23")
        firewall.add_rule("BLOCK PORT 21")
    
    # Mostrar regras carregadas
    print("\n[REGRA] REGRAS CARREGADAS:")
    print("-" * 70)
    for idx, rule in enumerate(firewall.rules, 1):
        action_display = "PERMITIR" if rule['action'] == 'ALLOW' else "BLOQUEAR"
        tipo_display = "IP" if rule['type'] == 'IP' else "PORTA"
        print(f"  {idx}. {action_display:10s} {tipo_display:6s} {rule['value']}")
    print("-" * 70)
    print(f"\nPolítica padrão (quando nenhuma regra corresponde): {firewall.default_policy}")
    
    time.sleep(1)
    
    # Demonstração 1: Pacote bloqueado por IP
    print_header("CENARIO 1: Pacote Bloqueado por IP")
    print("\n[TESTE] Tentando acessar de um IP bloqueado...")
    print_packet_test(firewall, "192.168.1.100", 80, "TCP")
    print("   [!] Este IP esta na lista de bloqueados!")
    
    time.sleep(1)
    
    # Demonstração 2: Pacote permitido por IP diferente
    print_header("CENARIO 2: Pacote Permitido (IP nao bloqueado)")
    print("\n[TESTE] Tentando acessar de um IP permitido...")
    print_packet_test(firewall, "192.168.1.200", 80, "TCP")
    print("   [OK] IP nao esta bloqueado e a porta 80 esta permitida!")
    
    time.sleep(1)
    
    # Demonstração 3: Pacote bloqueado por porta
    print_header("CENARIO 3: Pacote Bloqueado por Porta")
    print("\n[TESTE] Tentando acessar uma porta bloqueada...")
    print_packet_test(firewall, "192.168.1.200", 23, "TCP")
    print("   [!] A porta 23 (Telnet) esta bloqueada por seguranca!")
    
    time.sleep(1)
    
    # Demonstração 4: Pacote permitido por porta permitida
    print_header("CENARIO 4: Pacote Permitido (Porta HTTPS)")
    print("\n[TESTE] Tentando acessar porta HTTPS (443)...")
    print_packet_test(firewall, "192.168.1.200", 443, "TCP")
    print("   [OK] Porta 443 (HTTPS) esta permitida!")
    
    time.sleep(1)
    
    # Demonstração 5: Primeira regra que corresponde decide
    print_header("CENARIO 5: Ordem das Regras Importa!")
    print("\n[TESTE] Testando IP bloqueado tentando acessar porta permitida...")
    print("   (A primeira regra correspondente decide a acao)")
    print_packet_test(firewall, "192.168.1.100", 443, "TCP")
    print("   [!] Mesmo que a porta 443 seja permitida, o IP esta bloqueado!")
    print("   [INFO] A regra de IP aparece primeiro, entao ela decide.")
    
    time.sleep(1)
    
    # Demonstração 6: Usando política padrão
    print_header("CENARIO 6: Usando Politica Padrao")
    print("\n[TESTE] Tentando acessar porta nao especificada nas regras...")
    print_packet_test(firewall, "192.168.1.200", 8080, "TCP")
    print("   [INFO] Nenhuma regra corresponde, entao usa politica padrao: ALLOW")
    
    # Resumo final
    print_header("RESUMO DA DEMONSTRACAO")
    print("\n[STATS] Estatisticas:")
    
    # Contar testes
    testes = [
        ("192.168.1.100", 80, "TCP"),    # Bloqueado por IP
        ("192.168.1.200", 80, "TCP"),    # Permitido
        ("192.168.1.200", 23, "TCP"),    # Bloqueado por porta
        ("192.168.1.200", 443, "TCP"),   # Permitido
        ("192.168.1.100", 443, "TCP"),   # Bloqueado por IP
        ("192.168.1.200", 8080, "TCP"),  # Permitido (padrão)
    ]
    
    permitidos = 0
    bloqueados = 0
    
    for ip, port, proto in testes:
        if firewall.evaluate_packet(ip, port, proto) == "ALLOW":
            permitidos += 1
        else:
            bloqueados += 1
    
    print(f"   Total de pacotes testados: {len(testes)}")
    print(f"   [OK] Permitidos: {permitidos}")
    print(f"   [X] Bloqueados: {bloqueados}")
    
    print("\n" + "=" * 70)
    print("  Demonstracao concluida!")
    print("=" * 70)
    print("\n[DICA] Use o modo interativo para testar seus proprios pacotes:")
    print("   python main.py --rules regras_exemplo.txt --interactive")
    print()

if __name__ == "__main__":
    main()

