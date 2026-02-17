"""
asset_manager.py

Enterprise asset inventory generator + loader for RBVM orchestration.
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

import pandas as pd


@dataclass(frozen=True)
class AssetRecord:
    """Represents a single enterprise asset entry."""
    asset_name: str
    os_platform: str
    data_sensitivity_score: int  # 1-10
    network_exposure_score: int  # 1-5


class AssetManager:
    """Manages generation and loading of an enterprise asset inventory CSV."""

    REQUIRED_COLUMNS = [
        "Asset_Name",
        "OS_Platform",
        "Data_Sensitivity_Score",
        "Network_Exposure_Score",
    ]

    def __init__(self, csv_path: str = "assets_enterprise.csv") -> None:
        """Initializes the AssetManager.

        Args:
            csv_path: Output CSV filename/path for the enterprise asset inventory.
        """
        self.csv_path = Path(csv_path)
        self.logger = logging.getLogger(self.__class__.__name__)

    def generate_enterprise_assets(self) -> List[AssetRecord]:
        """Generates a realistic set of 20 enterprise assets.

        Returns:
            A list of AssetRecord entries (length = 20).
        """
        assets: List[AssetRecord] = [
            AssetRecord("Core_Database_01", "Linux (RHEL)", 10, 2),
            AssetRecord("Core_Database_02", "Linux (RHEL)", 9, 2),
            AssetRecord("Payment_API_Gateway_01", "Linux (Ubuntu LTS)", 9, 4),
            AssetRecord("IAM_Directory_01", "Windows Server 2019", 10, 3),
            AssetRecord("SIEM_Collector_01", "Linux (Ubuntu LTS)", 8, 3),
            AssetRecord("Backup_Vault_01", "Linux (RHEL)", 10, 1),
            AssetRecord("Finance_App_Server_01", "Windows Server 2022", 9, 3),
            AssetRecord("HR_App_Server_01", "Windows Server 2019", 8, 3),
            AssetRecord("CRM_App_Server_01", "Linux (Ubuntu LTS)", 7, 3),
            AssetRecord("Data_Warehouse_01", "Linux (RHEL)", 9, 2),
            AssetRecord("Edge_Router_Alpha", "Network OS (IOS-XE)", 6, 5),
            AssetRecord("Edge_Firewall_01", "Network OS (PAN-OS)", 8, 5),
            AssetRecord("Branch_Switch_07", "Network OS (NX-OS)", 5, 4),
            AssetRecord("Wireless_Controller_01", "Network OS (ArubaOS)", 6, 4),
            AssetRecord("VPN_Concentrator_01", "Network OS (ASA/FTD)", 7, 5),
            AssetRecord("Email_Transport_01", "Linux (Debian)", 8, 4),
            AssetRecord("Internal_Web_Portal_01", "Linux (Ubuntu LTS)", 6, 3),
            AssetRecord("DevOps_Jenkins_01", "Linux (Ubuntu LTS)", 7, 3),
            AssetRecord("Employee_Workstation_12", "Windows 11", 4, 2),
            AssetRecord("Employee_Workstation_27", "macOS", 5, 2),
        ]
        return assets

    def write_assets_csv(self, overwrite: bool = True) -> Path:
        """Writes the enterprise asset inventory to CSV.

        Args:
            overwrite: If False and file exists, raise an error.

        Returns:
            Path to the created CSV file.

        Raises:
            FileExistsError: If overwrite is False and the file already exists.
            ValueError: If any generated record violates expected score ranges.
            RuntimeError: On I/O failures.
        """
        assets = self.generate_enterprise_assets()

        # Validate score ranges (defensive).
        for a in assets:
            if not (1 <= a.data_sensitivity_score <= 10):
                raise ValueError(f"Invalid Data_Sensitivity_Score for {a.asset_name}: {a.data_sensitivity_score}")
            if not (1 <= a.network_exposure_score <= 5):
                raise ValueError(f"Invalid Network_Exposure_Score for {a.asset_name}: {a.network_exposure_score}")

        if self.csv_path.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {self.csv_path}")

        try:
            with self.csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.REQUIRED_COLUMNS)
                writer.writeheader()
                for a in assets:
                    writer.writerow(
                        {
                            "Asset_Name": a.asset_name,
                            "OS_Platform": a.os_platform,
                            "Data_Sensitivity_Score": a.data_sensitivity_score,
                            "Network_Exposure_Score": a.network_exposure_score,
                        }
                    )

            self.logger.info("Wrote %d assets to %s", len(assets), self.csv_path)
            return self.csv_path

        except OSError as exc:
            raise RuntimeError(f"Failed to write asset CSV: {exc}") from exc

    def load_assets_dataframe(self) -> pd.DataFrame:
        """Loads the enterprise asset inventory CSV into a Pandas DataFrame.

        Returns:
            DataFrame containing the asset inventory.

        Raises:
            FileNotFoundError: If the CSV does not exist.
            ValueError: If required columns are missing or types are invalid.
            RuntimeError: On parse failures.
        """
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Asset inventory CSV not found: {self.csv_path}")

        try:
            df = pd.read_csv(self.csv_path)

            missing = [c for c in self.REQUIRED_COLUMNS if c not in df.columns]
            if missing:
                raise ValueError(f"Asset CSV missing required columns: {missing}")

            # Enforce numeric types for scoring columns.
            df["Data_Sensitivity_Score"] = pd.to_numeric(df["Data_Sensitivity_Score"], errors="raise").astype(int)
            df["Network_Exposure_Score"] = pd.to_numeric(df["Network_Exposure_Score"], errors="raise").astype(int)

            # Range checks.
            if ((df["Data_Sensitivity_Score"] < 1) | (df["Data_Sensitivity_Score"] > 10)).any():
                raise ValueError("Data_Sensitivity_Score must be in range 1-10.")
            if ((df["Network_Exposure_Score"] < 1) | (df["Network_Exposure_Score"] > 5)).any():
                raise ValueError("Network_Exposure_Score must be in range 1-5.")

            return df

        except (pd.errors.ParserError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"Failed to parse asset CSV: {exc}") from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    am = AssetManager()
    am.write_assets_csv(overwrite=True)
    df_assets = am.load_assets_dataframe()
    print(df_assets.head())
