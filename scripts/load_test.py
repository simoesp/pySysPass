"""Mixed-workload load test for a running pySysPass stack (R16 / #65).

Run against a disposable stack only: it installs (if needed) and creates data.

    python scripts/load_test.py --base-url http://127.0.0.1:18200 --users 20 --duration 60

Each virtual user signs in once, then loops over a weighted mix of reads and
writes through the public API (nginx -> backend). Optionally a full backup is
started mid-run to measure the effect of a slow operation. Prints a JSON
summary with request counts, throughput, latency percentiles, errors, and
per-window throughput and p95 (to spot degradation over a soak run).

Long runs refresh each token every --refresh-every seconds, as the SPA does,
so they outlive the session inactivity timeout. With --seed-accounts 0 the
run uses the accounts already present (e.g. a large SQL-seeded dataset).
"""
import argparse
import asyncio
import json
import random
import statistics
import time
from collections import defaultdict

import httpx

MIX = [  # (operation, weight)
    ("list_accounts", 45),
    ("get_account", 20),
    ("reveal_password", 15),
    ("search", 10),
    ("create_account", 7),
    ("update_account", 3),
]


def _percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[index] * 1000, 1)


class LoadTest:
    def __init__(self, args):
        self.args = args
        self.api = args.base_url.rstrip("/") + "/api/v1"
        self.latencies = defaultdict(list)
        self.errors = defaultdict(int)
        self.account_ids = []
        self.refs = {}
        self.timeline = []  # (seconds since start, latency) of every timed call
        self.started = None

    async def _login(self, client):
        response = await client.post(f"{self.api}/auth/login", data={
            "username": self.args.admin_user, "password": self.args.admin_password,
            "mpass": self.args.master_password,
        })
        response.raise_for_status()
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def setup(self):
        async with httpx.AsyncClient(timeout=60) as client:
            status = (await client.get(f"{self.api}/auth/install/status")).json()
            if not status.get("installed"):
                response = await client.post(f"{self.api}/auth/install", json={
                    "username": self.args.admin_user, "password": self.args.admin_password,
                    "master_password": self.args.master_password, "generate_master_password": False,
                    "email": "loadtest@example.invalid",
                })
                response.raise_for_status()
            headers = await self._login(client)
            client_id = (await client.post(f"{self.api}/clients", json={"name": f"lt-{time.time_ns()}"},
                                           headers=headers)).json()["id"]
            category_id = (await client.post(f"{self.api}/categories", json={"name": f"lt-{time.time_ns()}"},
                                             headers=headers)).json()["id"]
            self.refs = {"client_id": client_id, "category_id": category_id}
            if self.args.seed_accounts == 0:
                skip = 0
                while True:
                    page = (await client.get(f"{self.api}/accounts", params={"skip": skip, "limit": 500},
                                             headers=headers)).json()
                    self.account_ids.extend(item["id"] for item in page)
                    if len(page) < 500:
                        break
                    skip += 500
            for index in range(self.args.seed_accounts):
                response = await client.post(f"{self.api}/accounts", headers=headers, json={
                    "title": f"seed {index}", "login": f"user{index}", "password": f"seed-secret-{index}",
                    "url": "https://example.invalid", "is_public": True, **self.refs,
                })
                response.raise_for_status()
                self.account_ids.append(response.json()["id"])

    async def _call(self, name, coroutine):
        started = time.perf_counter()
        try:
            response = await coroutine
            ok = response.status_code < 400
        except httpx.HTTPError:
            ok = False
            response = None
        self.latencies[name].append(time.perf_counter() - started)
        if self.started is not None:
            self.timeline.append((started - self.started, time.perf_counter() - started))
        if not ok:
            self.errors[f"{name}:{response.status_code if response is not None else 'transport'}"] += 1
        return response

    async def _operation(self, client, headers, name):
        account_id = random.choice(self.account_ids)
        if name == "list_accounts":
            return await self._call(name, client.get(f"{self.api}/accounts", headers=headers))
        if name == "get_account":
            return await self._call(name, client.get(f"{self.api}/accounts/{account_id}", headers=headers))
        if name == "reveal_password":
            return await self._call(name, client.get(f"{self.api}/accounts/{account_id}/password", headers=headers))
        if name == "search":
            return await self._call(name, client.get(f"{self.api}/accounts/search", params={"q": self.args.search},
                                                     headers=headers))
        if name == "create_account":
            response = await self._call(name, client.post(f"{self.api}/accounts", headers=headers, json={
                "title": f"lt {time.time_ns()}", "password": "load-test-secret", "is_public": True, **self.refs,
            }))
            if response is not None and response.status_code == 201:
                self.account_ids.append(response.json()["id"])
            return response
        return await self._call(name, client.put(f"{self.api}/accounts/{account_id}", headers=headers,
                                                 json={"notes": f"touched {time.time_ns()}"}))

    async def virtual_user(self, deadline):
        names, weights = zip(*MIX)
        async with httpx.AsyncClient(timeout=30) as client:
            started = time.perf_counter()
            headers = await self._login(client)
            self.latencies["login"].append(time.perf_counter() - started)
            refreshed = time.perf_counter()
            while time.perf_counter() < deadline:
                if time.perf_counter() - refreshed > self.args.refresh_every:
                    response = await self._call("refresh", client.post(f"{self.api}/auth/refresh", headers=headers))
                    if response is not None and response.status_code == 200:
                        headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
                    refreshed = time.perf_counter()
                await self._operation(client, headers, random.choices(names, weights)[0])

    async def slow_backup(self, delay):
        await asyncio.sleep(delay)
        async with httpx.AsyncClient(timeout=600) as client:
            headers = await self._login(client)
            await self._call("backup_create", client.post(f"{self.api}/backup/create", headers=headers))

    async def run(self):
        await self.setup()
        started = self.started = time.perf_counter()
        deadline = started + self.args.duration
        tasks = [self.virtual_user(deadline) for _ in range(self.args.users)]
        if self.args.backup_at is not None:
            tasks.append(self.slow_backup(self.args.backup_at))
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - started
        operations = {
            name: {
                "count": len(values), "p50_ms": _percentile(values, 50), "p95_ms": _percentile(values, 95),
                "p99_ms": _percentile(values, 99), "max_ms": round(max(values) * 1000, 1),
                "mean_ms": round(statistics.fmean(values) * 1000, 1),
            }
            for name, values in sorted(self.latencies.items())
        }
        total = sum(len(v) for k, v in self.latencies.items() if k not in ("login", "backup_create"))
        windows = defaultdict(list)
        for offset, latency in self.timeline:
            windows[int(offset // self.args.window)].append(latency)
        timeline = [
            {"from_s": index * self.args.window, "rps": round(len(values) / self.args.window, 1),
             "p95_ms": _percentile(values, 95)}
            for index, values in sorted(windows.items())
        ]
        return {
            "users": self.args.users, "duration_s": round(elapsed, 1), "requests": total,
            "throughput_rps": round(total / elapsed, 1), "error_count": sum(self.errors.values()),
            "errors": dict(self.errors), "operations": operations, "accounts": len(self.account_ids),
            "timeline": timeline,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--users", type=int, default=10)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--seed-accounts", type=int, default=200)
    parser.add_argument("--backup-at", type=float, default=None, help="Start a full backup after N seconds")
    parser.add_argument("--search", default="seed 1", help="Search term for the search operation")
    parser.add_argument("--refresh-every", type=float, default=120, help="Refresh each token after N seconds")
    parser.add_argument("--window", type=int, default=60, help="Timeline window in seconds")
    parser.add_argument("--admin-user", default="loadadmin")
    parser.add_argument("--admin-password", default="load-test-admin-password")
    parser.add_argument("--master-password", default="load-test-master-password")
    print(json.dumps(asyncio.run(LoadTest(parser.parse_args()).run()), indent=2))


if __name__ == "__main__":
    main()
