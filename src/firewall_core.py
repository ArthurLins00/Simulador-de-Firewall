class FirewallSimulator:
    """
    Simulador de firewall para filtragem de pacotes baseada em regras
    """
    
    def __init__(self, default_policy="ALLOW"):
        self.rules = []
        self.default_policy = default_policy
    
    def load_rules(self, filename):
        """
        Carrega regras de arquivo de configuração
        Args:
            filename (str): Caminho do arquivo de regras
        """
        pass
    
    def add_rule(self, rule_string):
        """
        Adiciona uma regra a partir de string
        Args:
            rule_string (str): Regra no formato 'ACTION TIPO VALOR'
        """
        pass
    
    def evaluate_packet(self, src_ip, dst_port, protocol="TCP"):
        """
        Avalia um pacote contra todas as regras
        Args:
            src_ip (str): IP de origem
            dst_port (int): Porta de destino
            protocol (str): Protocolo (TCP/UDP)
        Returns:
            str: "ALLOW" ou "BLOCK"
        """
        pass
    
    def _parse_rule(self, rule_string):
        """
        Interpreta string de regra e converte para objeto
        """
        pass
    
    def _matches_rule(self, packet, rule):
        """
        Verifica se pacote corresponde à regra
        """
        pass