"""
Configuration module for the secure voting system.

This module contains all configurable parameters and constants
used throughout the voting system to ensure consistency and
easy maintenance.
"""

from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class CryptoConfig:
    """Cryptographic configuration parameters"""
    
    # Paillier encryption parameters
    PRIME_MIN_VAL: int = 50
    PRIME_MAX_VAL: int = 80
    
    # Sigma protocol parameters
    SCHNORR_GENERATOR: int = 2
    SCHNORR_PRIME: int = 11835969984353354216691437291006245763846242542829548494585386007353171784095072175673343062339173975526279362680161974682108208645413677644629654572794703
    
    # Security levels
    MIN_KEY_SIZE_BITS: int = 512

@dataclass
class SystemConfig:
    """System-wide configuration parameters"""
    
    # Logging and output
    VERBOSE_OUTPUT: bool = True
    LOG_CRYPTO_OPERATIONS: bool = False
    SHOW_INTERMEDIATE_RESULTS: bool = True
    
    # Validation parameters
    MAX_VOTERS: int = 10000
    MIN_VOTERS: int = 1
    TIMEOUT_SECONDS: int = 30
    
    # Test configuration
    ENABLE_FRAUD_SIMULATION: bool = True
    DEFAULT_TEST_VOTER_COUNT: int = 5

@dataclass
class NetworkConfig:
    """Network and communication configuration"""
    
    # In this simulation, these would be used for actual network communication
    CLIENT_PORT: int = 8001
    SERVER_PORT: int = 8002
    SIMULATOR_PORT: int = 8003
    
    # Message formatting
    MESSAGE_ENCODING: str = 'utf-8'
    MAX_MESSAGE_SIZE: int = 1024 * 1024  # 1MB

class VotingSystemConfig:
    """Main configuration class combining all config sections"""
    
    def __init__(self):
        self.crypto = CryptoConfig()
        self.system = SystemConfig()
        self.network = NetworkConfig()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization"""
        return {
            'crypto': {
                'prime_min_val': self.crypto.PRIME_MIN_VAL,
                'prime_max_val': self.crypto.PRIME_MAX_VAL,
                'schnorr_generator': self.crypto.SCHNORR_GENERATOR,
                'min_key_size_bits': self.crypto.MIN_KEY_SIZE_BITS,
            },
            'system': {
                'verbose_output': self.system.VERBOSE_OUTPUT,
                'log_crypto_operations': self.system.LOG_CRYPTO_OPERATIONS,
                'max_voters': self.system.MAX_VOTERS,
                'min_voters': self.system.MIN_VOTERS,
                'timeout_seconds': self.system.TIMEOUT_SECONDS,
            },
            'network': {
                'client_port': self.network.CLIENT_PORT,
                'server_port': self.network.SERVER_PORT,
                'simulator_port': self.network.SIMULATOR_PORT,
                'message_encoding': self.network.MESSAGE_ENCODING,
                'max_message_size': self.network.MAX_MESSAGE_SIZE,
            }
        }
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'VotingSystemConfig':
        """Create configuration from dictionary"""
        config = cls()
        
        if 'crypto' in config_dict:
            crypto_config = config_dict['crypto']
            config.crypto.PRIME_MIN_VAL = crypto_config.get('prime_min_val', config.crypto.PRIME_MIN_VAL)
            config.crypto.PRIME_MAX_VAL = crypto_config.get('prime_max_val', config.crypto.PRIME_MAX_VAL)
            config.crypto.SCHNORR_GENERATOR = crypto_config.get('schnorr_generator', config.crypto.SCHNORR_GENERATOR)
            config.crypto.MIN_KEY_SIZE_BITS = crypto_config.get('min_key_size_bits', config.crypto.MIN_KEY_SIZE_BITS)
        
        if 'system' in config_dict:
            system_config = config_dict['system']
            config.system.VERBOSE_OUTPUT = system_config.get('verbose_output', config.system.VERBOSE_OUTPUT)
            config.system.LOG_CRYPTO_OPERATIONS = system_config.get('log_crypto_operations', config.system.LOG_CRYPTO_OPERATIONS)
            config.system.MAX_VOTERS = system_config.get('max_voters', config.system.MAX_VOTERS)
            config.system.MIN_VOTERS = system_config.get('min_voters', config.system.MIN_VOTERS)
            config.system.TIMEOUT_SECONDS = system_config.get('timeout_seconds', config.system.TIMEOUT_SECONDS)
        
        if 'network' in config_dict:
            network_config = config_dict['network']
            config.network.CLIENT_PORT = network_config.get('client_port', config.network.CLIENT_PORT)
            config.network.SERVER_PORT = network_config.get('server_port', config.network.SERVER_PORT)
            config.network.SIMULATOR_PORT = network_config.get('simulator_port', config.network.SIMULATOR_PORT)
            config.network.MESSAGE_ENCODING = network_config.get('message_encoding', config.network.MESSAGE_ENCODING)
            config.network.MAX_MESSAGE_SIZE = network_config.get('max_message_size', config.network.MAX_MESSAGE_SIZE)
            
        return config
    
    def validate(self) -> bool:
        """Validate configuration parameters"""
        try:
            # Validate crypto parameters
            assert self.crypto.PRIME_MIN_VAL > 0, "Prime min value must be positive"
            assert self.crypto.PRIME_MAX_VAL > self.crypto.PRIME_MIN_VAL, "Prime max must be greater than min"
            assert self.crypto.SCHNORR_GENERATOR > 1, "Generator must be greater than 1"
            assert self.crypto.MIN_KEY_SIZE_BITS >= 256, "Minimum key size too small for security"
            
            # Validate system parameters
            assert self.system.MAX_VOTERS > 0, "Max voters must be positive"
            assert self.system.MIN_VOTERS > 0, "Min voters must be positive"
            assert self.system.MAX_VOTERS >= self.system.MIN_VOTERS, "Max voters must be >= min voters"
            assert self.system.TIMEOUT_SECONDS > 0, "Timeout must be positive"
            
            # Validate network parameters
            assert 1024 <= self.network.CLIENT_PORT <= 65535, "Invalid client port"
            assert 1024 <= self.network.SERVER_PORT <= 65535, "Invalid server port"
            assert 1024 <= self.network.SIMULATOR_PORT <= 65535, "Invalid simulator port"
            assert self.network.MAX_MESSAGE_SIZE > 0, "Max message size must be positive"
            
            return True
            
        except AssertionError as e:
            print(f"Configuration validation failed: {e}")
            return False

# Global configuration instance
DEFAULT_CONFIG = VotingSystemConfig()

# Convenience functions for accessing common config values
def get_crypto_config() -> CryptoConfig:
    """Get cryptographic configuration"""
    return DEFAULT_CONFIG.crypto

def get_system_config() -> SystemConfig:
    """Get system configuration"""
    return DEFAULT_CONFIG.system

def get_network_config() -> NetworkConfig:
    """Get network configuration"""
    return DEFAULT_CONFIG.network