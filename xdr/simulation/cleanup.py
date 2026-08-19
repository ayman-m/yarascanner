#!/usr/bin/env python3
"""Remove every dataset this simulation created. Matches on SIM_PREFIX only, so it can
never touch a real scanner dataset."""
from simlib import SIM_PREFIX, banner, client

banner(f"cleanup — deleting datasets prefixed {SIM_PREFIX!r}")
ac = client()
ds = ac.reply("/public_api/v1/xql/get_datasets/", {})
names = [d.get("Dataset Name") for d in ds if str(d.get("Dataset Name", "")).startswith(SIM_PREFIX)]
print(f"{len(names)} simulation dataset(s) to remove")
for n in names:
    try:
        print(f"  {n}: {ac.delete_dataset(n)}")
    except Exception as e:
        print(f"  {n}: FAILED {str(e)[:120]}")
