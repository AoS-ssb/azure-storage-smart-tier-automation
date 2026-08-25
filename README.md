# Azure Blob Storage smart tier automation

Audit-first Azure Automation runbook that enables **Azure Blob Storage smart tier** (`accessTier = Smart`)
on eligible, explicitly opted-in storage accounts, with a change cap and per-account verification.

> **Status:** version 1.0 is the runbook exactly as published in the owner's Azure Automation account on
> 2026-08-24 (SHA-256 of `src/Enable-AzStorageSmartTier.ps1` recorded in `docs/validation.md`). An
> adversarial multi-model review is in progress; version 1.1 will follow the same structure as the
> sibling project [azure-backup-smart-tiering-automation](https://github.com/AoS-ssb/azure-backup-smart-tiering-automation).

This is **not** Azure Backup "Smart Tiering" (recovery points → vault-archive); that is a different
product with its own repository. This runbook changes only a storage account's default blob access tier.
