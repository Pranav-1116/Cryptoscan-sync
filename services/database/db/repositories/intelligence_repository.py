"""Business process / owner / vendor / migration / TLS target helpers."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.business_owner import BusinessOwner
from db.models.business_process import BusinessProcess
from db.models.cloud_account import CloudAccount
from db.models.migration_project import MigrationProject
from db.models.network_scan_target import NetworkScanTarget
from db.models.system_business_process import SystemBusinessProcess
from db.models.vendor import SystemVendor, Vendor


class IntelligenceRepository:
    def __init__(self, session: Session):
        self.session = session

    def list_processes(self) -> list[BusinessProcess]:
        return list(self.session.execute(select(BusinessProcess).order_by(BusinessProcess.name)).scalars())

    def create_process(self, **kwargs) -> BusinessProcess:
        row = BusinessProcess(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def link_process(self, system_id: str, process_id: str, role: str | None = "PRIMARY") -> SystemBusinessProcess:
        existing = self.session.execute(
            select(SystemBusinessProcess).where(
                SystemBusinessProcess.system_id == system_id,
                SystemBusinessProcess.process_id == process_id,
            )
        ).scalar_one_or_none()
        if existing:
            return existing
        row = SystemBusinessProcess(system_id=system_id, process_id=process_id, role=role)
        self.session.add(row)
        self.session.flush()
        return row

    def process_system_ids(self, process_id: str) -> list[str]:
        rows = self.session.execute(
            select(SystemBusinessProcess.system_id).where(SystemBusinessProcess.process_id == process_id)
        ).scalars()
        return list(rows)

    def list_owners(self) -> list[BusinessOwner]:
        return list(self.session.execute(select(BusinessOwner).order_by(BusinessOwner.name)).scalars())

    def create_owner(self, **kwargs) -> BusinessOwner:
        row = BusinessOwner(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def list_targets(self) -> list[NetworkScanTarget]:
        return list(self.session.execute(select(NetworkScanTarget).order_by(NetworkScanTarget.endpoint)).scalars())

    def upsert_target(self, endpoint: str, **kwargs) -> NetworkScanTarget:
        row = self.session.execute(
            select(NetworkScanTarget).where(NetworkScanTarget.endpoint == endpoint)
        ).scalar_one_or_none()
        if row:
            for key, value in kwargs.items():
                if hasattr(row, key) and value is not None:
                    setattr(row, key, value)
            self.session.flush()
            return row
        row = NetworkScanTarget(endpoint=endpoint, **kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def list_cloud_accounts(self) -> list[CloudAccount]:
        return list(self.session.execute(select(CloudAccount)).scalars())

    def get_cloud_account(self, account_id: str) -> CloudAccount | None:
        return self.session.get(CloudAccount, account_id)

    def find_cloud_account(self, provider: str | None, identifier: str | None) -> CloudAccount | None:
        from sqlalchemy import func

        stmt = select(CloudAccount)
        if provider:
            stmt = stmt.where(func.upper(CloudAccount.cloud_provider) == provider.upper())
        if identifier:
            stmt = stmt.where(CloudAccount.account_identifier == identifier)
        return self.session.execute(stmt.limit(1)).scalar_one_or_none()

    def create_cloud_account(self, **kwargs) -> CloudAccount:
        row = CloudAccount(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def list_vendors(self) -> list[Vendor]:
        return list(self.session.execute(select(Vendor).order_by(Vendor.name)).scalars())

    def create_vendor(self, name: str, criticality: str | None = None, **kwargs) -> Vendor:
        existing = self.session.execute(select(Vendor).where(Vendor.name == name)).scalar_one_or_none()
        if existing:
            if criticality and not existing.criticality:
                existing.criticality = criticality
            for key, value in kwargs.items():
                if hasattr(existing, key) and value is not None:
                    setattr(existing, key, value)
            self.session.flush()
            return existing
        allowed = {
            "vendor_type",
            "contract_end_date",
            "data_classifications",
            "integration_type",
            "primary_contact",
            "security_contact",
            "extra",
            "extra_json",
        }
        fields = {key: value for key, value in kwargs.items() if key in allowed}
        row = Vendor(name=name, criticality=criticality, **fields)
        self.session.add(row)
        self.session.flush()
        return row

    def get_vendor(self, vendor_id: str) -> Vendor | None:
        return self.session.get(Vendor, vendor_id)

    def update_vendor(self, vendor_id: str, **kwargs) -> Vendor | None:
        row = self.get_vendor(vendor_id)
        if row is None:
            return None
        for key, value in kwargs.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
        self.session.flush()
        return row

    def link_vendor(self, system_id: str, vendor_id: str) -> SystemVendor:
        existing = self.session.execute(
            select(SystemVendor).where(SystemVendor.system_id == system_id, SystemVendor.vendor_id == vendor_id)
        ).scalar_one_or_none()
        if existing:
            return existing
        row = SystemVendor(system_id=system_id, vendor_id=vendor_id)
        self.session.add(row)
        self.session.flush()
        return row

    def vendor_system_ids(self, vendor_id: str) -> list[str]:
        return list(
            self.session.execute(select(SystemVendor.system_id).where(SystemVendor.vendor_id == vendor_id)).scalars()
        )

    def list_migrations(self) -> list[MigrationProject]:
        return list(self.session.execute(select(MigrationProject).order_by(MigrationProject.created_at.desc())).scalars())

    def create_migration(self, **kwargs) -> MigrationProject:
        row = MigrationProject(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def update_migration(self, project_id: str, **kwargs) -> MigrationProject | None:
        row = self.session.get(MigrationProject, project_id)
        if row is None:
            return None
        for key, value in kwargs.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
        self.session.flush()
        return row
