"""
Tests for payload management
"""

import pytest
from sqlinjector.payloads import PayloadManager, get_boolean_payloads
from sqlinjector.models import InjectionType, DatabaseType


class TestPayloadManager:
    
    def test_payload_manager_creation(self):
        """Test creating payload manager"""
        manager = PayloadManager()
        
        assert isinstance(manager.payloads, dict)
        assert len(manager.payloads) > 0
        assert InjectionType.BOOLEAN_BLIND in manager.payloads
    
    def test_get_boolean_payloads(self, payload_manager):
        """Test getting boolean injection payloads"""
        payloads = payload_manager.get_payloads(InjectionType.BOOLEAN_BLIND, limit=5)
        
        assert len(payloads) == 5
        assert all(isinstance(p, str) for p in payloads)
        assert any("OR" in p for p in payloads)
    
    def test_get_time_payloads(self, payload_manager):
        """Test getting time-based injection payloads"""
        payloads = payload_manager.get_payloads(InjectionType.TIME_BLIND, limit=3)
        
        assert len(payloads) == 3
        assert any("SLEEP" in p or "WAITFOR" in p for p in payloads)
    
    def test_get_union_payloads(self, payload_manager):
        """Test getting UNION-based injection payloads"""
        payloads = payload_manager.get_payloads(InjectionType.UNION_BASED, limit=5)
        
        assert len(payloads) == 5
        assert any("UNION" in p for p in payloads)
    
    def test_get_database_specific_payloads(self, payload_manager):
        """Test getting database-specific payloads"""
        mysql_payloads = payload_manager.get_payloads(
            InjectionType.UNION_BASED, 
            database_type=DatabaseType.MYSQL,
            limit=3
        )
        
        assert len(mysql_payloads) >= 3
        # Should include both generic and MySQL-specific payloads
    
    def test_custom_payload_generation(self, payload_manager):
        """Test custom payload generation"""
        custom_payload = payload_manager.generate_custom_payload(
            InjectionType.BOOLEAN_BLIND,
            "test123"
        )
        
        assert "test123" in custom_payload
        assert "'" in custom_payload
    
    def test_add_custom_payloads(self, payload_manager):
        """Test adding custom payloads"""
        custom_payloads = ["' AND 1=1 /*custom*/", "' OR 1=1 /*custom*/"]
        
        initial_count = len(payload_manager.get_payloads(InjectionType.BOOLEAN_BLIND))
        payload_manager.add_custom_payloads(InjectionType.BOOLEAN_BLIND, custom_payloads)
        
        new_count = len(payload_manager.get_payloads(InjectionType.BOOLEAN_BLIND))
        assert new_count == initial_count + 2
    
    def test_payload_statistics(self, payload_manager):
        """Test payload statistics"""
        stats = payload_manager.get_payload_statistics()
        
        assert "boolean_blind" in stats
        assert "time_blind" in stats
        assert "union_based" in stats
        assert "total_all" in stats
        assert stats["total_all"] > 0


class TestQuickPayloadFunctions:
    
    def test_get_boolean_payloads_function(self):
        """Test quick boolean payloads function"""
        payloads = get_boolean_payloads(limit=3)
        
        assert len(payloads) == 3
        assert all(isinstance(p, str) for p in payloads)