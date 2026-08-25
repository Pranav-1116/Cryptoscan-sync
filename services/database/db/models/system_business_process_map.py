"""Spec-named alias of the system_business_process_map join table."""

from db.models.system_business_process import SystemBusinessProcess

SystemBusinessProcessMap = SystemBusinessProcess

__all__ = ["SystemBusinessProcess", "SystemBusinessProcessMap"]
