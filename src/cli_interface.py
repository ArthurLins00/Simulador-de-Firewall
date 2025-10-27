"""
Interface de linha de comando para o Firewall Simulator
"""

import argparse
from firewall_core import FirewallSimulator

def main():
    banner = """
    🔥 FIREWALL SIMULATOR 🔥
    Simulador de filtragem de pacotes baseado em regras
    ==================================================
    """
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='Firewall Simulator - Simulador de filtragem de pacotes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos de uso:
  python cli_interface.py --rules regras.txt --src-ip 192.168.1.100 --dst-port 80
  python cli_interface.py --rules regras.txt --interactive
        '''
    )
    
    parser.add_argument(
        '--rules', '-r', 
        required=True, 
        help='Arquivo contendo as regras de firewall'
    )
    parser.add_argument(
        '--src-ip', 
        help='IP de origem para simulação (ex: 192.168.1.100)'
    )
    parser.add_argument(
        '--dst-port', 
        type=int, 
        help='Porta de destino para simulação (ex: 80)'
    )
    parser.add_argument(
        '--protocol', 
        default='TCP', 
        choices=['TCP', 'UDP'],
        help='Protocolo do pacote (padrão: TCP)'
    )
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Modo interativo para testar múltiplos pacotes'
    )
    parser.add_argument(
        '--list-rules', '-l',
        action='store_true',
        help='Lista todas as regras carregadas'
    )
    
    args = parser.parse_args()
    
    # Inicializar firewall
    firewall = FirewallSimulator()
    
    try:
        # Carregar regras
        firewall.load_rules(args.rules)
        
        # Listar regras se solicitado
        if args.list_rules:
            firewall.list_rules()
        
        # Modo interativo
        if args.interactive:
            print("\n💻 Modo interativo ativo. Digite 'quit' para sair.")
            while True:
                try:
                    user_input = input("\n🎯 Digite pacote (IP:PORTA): ").strip()
                    if user_input.lower() in ['quit', 'exit', 'sair']:
                        break
                    
                    if ':' in user_input:
                        src_ip, dst_port = user_input.split(':', 1)
                        result = firewall.evaluate_packet(src_ip.strip(), int(dst_port.strip()))
                        print(f"✅ Resultado: {result}")
                    else:
                        print("❌ Formato inválido. Use: IP:PORTA")
                        
                except ValueError:
                    print("❌ Erro: Porta deve ser um número")
                except KeyboardInterrupt:
                    print("\n👋 Encerrando...")
                    break
        
        # Modo único pacote
        elif args.src_ip and args.dst_port:
            result = firewall.evaluate_packet(args.src_ip, args.dst_port, args.protocol)
            print(f"\n📊 RESUMO:")
            print(f"   Pacote: {args.src_ip} -> :{args.dst_port}/{args.protocol}")
            print(f"   Decisão: {result}")
            
        else:
            print("💡 Dica: Use --interactive para modo interativo ou forneça --src-ip e --dst-port")
            
    except Exception as e:
        print(f"❌ Erro durante execução: {e}")

if __name__ == "__main__":
    main()