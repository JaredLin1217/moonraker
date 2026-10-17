"""Bounded, sampled layer history. No motion commands or raw sample storage.

Layer boundaries follow the virtual SD read cursor, not execution time. Keep
that limitation in every response instead of implying measurement precision.
"""
from __future__ import annotations

import asyncio
import bisect
import copy
import json
import logging
import math
import re
import sqlite3
import time
import zlib
from array import array
from collections import deque
from pathlib import Path

from ..common import RequestType, SqlTableDefinition

JOBS = "layer_history_jobs"
LAYERS = "layer_history_layers"
SCHEMA_VERSION = 1
MAX_PENDING = 32
MAX_POINTS = 2000
MAX_INDEX_LAYERS = 500000
CHECKPOINT_SECONDS = 60.0
THERMAL_SECONDS = 1.0
MAX_SAMPLE_GAP = 2.0
CHANNELS = {
    "t0": "extruder", "t1": "extruder1", "bed": "heater_bed",
    "chamber": "heater_generic chamber",
}
FANS = {"fan": "fan", "hotend_fan": "fan_generic Hotend_Fan"}


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def pack(value):
    return zlib.compress(json.dumps(value, separators=(",", ":"), allow_nan=False).encode(), 1)


def unpack(value):
    return json.loads(zlib.decompress(value))


class JobsDefinition(SqlTableDefinition):
    name = JOBS
    version = 1
    prototype = f"{JOBS} (job_id INTEGER, start_time REAL, status TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY(job_id, start_time))"

    def migrate(self, last_version, db_provider):
        pass


class LayersDefinition(SqlTableDefinition):
    name = LAYERS
    version = 1
    prototype = f"{LAYERS} (job_id INTEGER, start_time REAL, layer INTEGER, data BLOB NOT NULL, PRIMARY KEY(job_id, start_time, layer))"

    def migrate(self, last_version, db_provider):
        pass


class LayerIndex:
    def __init__(self):
        self.offsets = array("Q")
        self.z = array("d")
        self.heights = array("d")
        self.end = 0

    @classmethod
    def scan(cls, path, metadata=None):
        index = cls()
        metadata = metadata or {}
        before = path.stat()
        offset = 0
        marker = re.compile(rb"^;\s*(?:LAYER_CHANGE|CHANGE_LAYER|LAYER:\s*-?\d+)\s*$")
        zline = re.compile(rb"^;\s*(Z|HEIGHT):\s*([-+0-9.eE]+)")
        with path.open("rb") as source:
            for line in source:
                stripped = line.strip()
                if marker.match(stripped):
                    if len(index.offsets) >= MAX_INDEX_LAYERS:
                        raise ValueError("layer_index_limit")
                    index.offsets.append(offset)
                    index.z.append(float("nan"))
                    index.heights.append(float("nan"))
                elif index.offsets:
                    match = zline.match(stripped)
                    if match:
                        value = float(match[2])
                        if math.isfinite(value):
                            (index.z if match[1] == b"Z" else index.heights)[-1] = value
                offset += len(line)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("gcode_changed")
        if not index.offsets:
            raise ValueError("no_layer_markers")
        index.end = int(metadata.get("gcode_end_byte") or offset)
        for pos in range(len(index.z)):
            if not math.isfinite(index.heights[pos]) and math.isfinite(index.z[pos]):
                previous = index.z[pos - 1] if pos else 0.0
                if math.isfinite(previous):
                    index.heights[pos] = index.z[pos] - previous
        return index

    def locate(self, offset):
        if offset >= self.end:
            return -1
        return bisect.bisect_right(self.offsets, max(0, offset))

    def dimensions(self, layer):
        pos = layer - 1
        return (number(self.z[pos]), number(self.heights[pos]))


class Moments:
    """Sufficient statistics, also used to combine chart buckets exactly."""
    def __init__(self, values=None):
        self.values = list(values) if values else [0.0, 0.0, None, None, 0]

    def add(self, value, seconds):
        value = number(value)
        if value is None or seconds <= 0:
            return False
        data = self.values
        data[0] += value * seconds
        data[1] += seconds
        data[2] = value if data[2] is None else min(data[2], value)
        data[3] = value if data[3] is None else max(data[3], value)
        data[4] += 1
        return True

    def merge(self, other):
        if not other[1]:
            return
        self.values[0] += other[0]
        self.values[1] += other[1]
        self.values[2] = other[2] if self.values[2] is None else min(self.values[2], other[2])
        self.values[3] = other[3] if self.values[3] is None else max(self.values[3], other[3])
        self.values[4] += other[4]

    def public(self):
        data = self.values
        return {"mean": data[0] / data[1] if data[1] else None, "min": data[2],
                "max": data[3], "seconds": data[1], "samples": data[4]}


class Accumulator:
    def __init__(self, layer, z=None, height=None):
        self.layer, self.z, self.height = layer, z, height
        self.active = self.paused = self.gap = 0.0
        self.stats = {}
        self.filament = {"t0": 0.0, "t1": 0.0}
        self.flags = set()
        self.complete = False

    def add(self, key, value, dt):
        if not self.stats.setdefault(key, Moments()).add(value, dt):
            self.flags.add("missing:" + key)

    def data(self):
        return {"l": self.layer, "z": self.z, "h": self.height, "a": self.active,
                "p": self.paused, "g": self.gap, "m": {k: v.values[:] for k, v in self.stats.items()},
                "e": dict(self.filament), "f": sorted(self.flags), "c": self.complete}


def public_row(data, diameters):
    filament = {}
    for tool, mm in data["e"].items():
        if "unobserved_layer" in data["f"]:
            mm = None
        diameter = diameters.get(tool)
        volume = mm * math.pi * (diameter / 2) ** 2 if diameter and mm is not None else None
        filament[tool] = {"mm": mm, "mm3": volume,
                          "mean_flow": volume / data["a"] if volume is not None and data["a"] else None}
    return {"layer": data["l"], "layer_end": data.get("le", data["l"]), "z": data["z"],
            "height": data["h"], "active_seconds": data["a"], "pause_seconds": data["p"],
            "gap_seconds": data["g"], "metrics": {k: Moments(v).public() for k, v in data["m"].items()},
            "filament": filament, "flags": data["f"], "complete": data["c"]}


def merge_rows(rows):
    first = copy.deepcopy(rows[0])
    first["le"] = rows[-1].get("le", rows[-1]["l"])
    first["z"] = first["h"] = None
    for other in rows[1:]:
        for key in ("a", "p", "g"):
            first[key] += other[key]
        for key, value in other["m"].items():
            stat = Moments(first["m"].get(key))
            stat.merge(value)
            first["m"][key] = stat.values
        for tool, value in other["e"].items():
            first["e"][tool] += value
        first["f"] = sorted(set(first["f"]) | set(other["f"]))
        first["c"] = first["c"] and other["c"]
    return first


class Recorder:
    """Pure replayable state machine. Inputs are shared Klipper status samples."""
    def __init__(self, index, diameters):
        self.index, self.diameters = index, diameters
        self.current = None
        self.total = Accumulator(0)
        self.last = None
        self.last_time = None
        self.last_thermal = None
        self.thermal_pending = 0.0
        self.last_checkpoint = None
        self.positions = {}
        self.highest = {}
        self.last_layer = self.closed_layers = self.skipped_layers = 0
        self.flags = {"approximate_layer_boundaries", "planned_motion_estimates"}
        self.stopped = False
        self.end_stage = False

    def state(self, status):
        return status.get("print_stats", {}).get("state", "standby")

    def observe_position(self, status, count):
        head = status.get("toolhead", {})
        tool = {"extruder": "t0", "extruder1": "t1"}.get(head.get("extruder"))
        pos = head.get("position", [])
        epos = number(pos[3]) if len(pos) > 3 else None
        if tool is None or epos is None:
            return
        if tool not in self.highest:
            self.highest[tool] = epos
            if count:
                self.current.flags.add("unobserved_tool_baseline:" + tool)
        elif count:
            used = max(0.0, epos - self.highest[tool])
            self.current.filament[tool] += used
            self.total.filament[tool] += used
            self.highest[tool] = max(self.highest[tool], epos)
        elif self.state(status) != "printing":
            self.highest[tool] = epos
        else:
            self.highest[tool] = max(self.highest[tool], epos)
        self.positions[tool] = epos

    def thermal(self, status, dt):
        if not self.current or dt <= 0:
            return
        for key, obj in CHANNELS.items():
            for field, suffix in (("temperature", ""), ("target", "_target")):
                value = status.get(obj, {}).get(field)
                for target in (self.current, self.total):
                    target.add(key + suffix, value, dt)
        for key, obj in FANS.items():
            value = number(status.get(obj, {}).get("speed"))
            for target in (self.current, self.total):
                target.add(key, value * 100 if value is not None else None, dt)

    def close_layer(self, complete):
        if self.current is None:
            return None
        self.current.complete = complete
        data = self.current.data()
        self.closed_layers += 1
        self.current = None
        return data

    def step(self, status, eventtime):
        ready = []
        if self.stopped:
            return ready
        if self.last_time is not None and eventtime <= self.last_time:
            return ready
        state = self.state(status)
        pos = status.get("virtual_sdcard", {}).get("file_position", 0)
        layer = self.index.locate(int(pos or 0))
        previous = self.last
        dt = eventtime - self.last_time if self.last_time is not None else 0.0
        previous_state = self.state(previous) if previous else state
        if self.current and previous:
            if dt > MAX_SAMPLE_GAP:
                self.current.gap += dt
                self.total.gap += dt
                self.current.flags.add("sample_gap")
                self.flags.add("sample_gap")
            elif previous_state == "paused":
                self.current.paused += dt
                self.total.paused += dt
            elif previous_state == "printing":
                self.current.active += dt
                self.total.active += dt
                motion = previous.get("motion_report", {})
                speed, evel = number(motion.get("live_velocity")), number(motion.get("live_extruder_velocity"))
                if speed is not None and evel is not None and speed > 0.0001:
                    key = "print_speed" if evel > 0.0001 else "travel_speed"
                    self.current.add(key, speed, dt)
                    self.total.add(key, speed, dt)
                self.thermal_pending += dt
                if self.thermal_pending >= THERMAL_SECONDS:
                    self.thermal(previous, self.thermal_pending)
                    self.thermal_pending = 0.0
                    self.last_thermal = eventtime
        self.observe_position(status, bool(self.current and previous_state == "printing" and
                                          state == "printing" and 0 < dt <= MAX_SAMPLE_GAP))
        if self.current and state != previous_state and self.thermal_pending and previous:
            self.thermal(previous, self.thermal_pending)
            self.thermal_pending = 0.0
        if self.current and (layer != self.current.layer or state not in ("printing", "paused")):
            if previous and self.thermal_pending:
                self.thermal(previous, self.thermal_pending)
                self.thermal_pending = 0.0
            data = self.close_layer(layer > 0 and layer != self.last_layer or layer == -1 or state == "complete")
            if data:
                ready.append(data)
            self.last_thermal = eventtime
        if layer > 0 and state in ("printing", "paused") and self.current is None:
            if layer <= self.last_layer:
                self.flags.add("file_cursor_rewind")
                self.stopped = True
            else:
                if layer > self.last_layer + 1:
                    self.skipped_layers += layer - self.last_layer - 1
                    self.flags.add("unobserved_layers")
                self.last_layer = layer
                self.current = Accumulator(layer, *self.index.dimensions(layer))
                self.last_thermal = self.last_checkpoint = eventtime
        if layer == -1:
            self.end_stage = True
        if self.current and (state == "paused" and previous_state != "paused" or
                             eventtime - self.last_checkpoint >= CHECKPOINT_SECONDS):
            ready.append(self.current.data())
            self.last_checkpoint = eventtime
        self.last, self.last_time = copy.deepcopy(status), eventtime
        return ready

    def finish(self, status, eventtime):
        rows = self.step(status, eventtime)
        if self.current:
            data = self.close_layer(status.get("print_stats", {}).get("state") == "complete")
            if data:
                rows.append(data)
        return rows

    def metadata(self):
        return {"schema_version": SCHEMA_VERSION, "approximate": True, "diameters": self.diameters,
                "max_layer": self.last_layer, "expected_layers": len(self.index.offsets),
                "closed_layers": self.closed_layers, "skipped_layers": self.skipped_layers,
                "flags": sorted(self.flags), "summary": self.total.data()}


def write_snapshot(conn, key, status, metadata, rows):
    """Identity check happens in the same worker transaction as every write."""
    with conn:
        exists = conn.execute("SELECT 1 FROM job_history WHERE job_id=? AND start_time=?", key).fetchone()
        if not exists:
            return False
        conn.execute(f"INSERT INTO {JOBS} VALUES(?,?,?,?) ON CONFLICT(job_id,start_time) DO UPDATE SET status=excluded.status,data=excluded.data",
                     (*key, status, pack(metadata)))
        conn.executemany(f"INSERT INTO {LAYERS} VALUES(?,?,?,?) ON CONFLICT(job_id,start_time,layer) DO UPDATE SET data=excluded.data",
                         [(*key, row["l"], pack(row)) for row in rows])
    return True


def delete_records(conn, identities, all_jobs):
    if all_jobs:
        conn.execute(f"DELETE FROM {LAYERS}")
        conn.execute(f"DELETE FROM {JOBS}")
    else:
        conn.executemany(f"DELETE FROM {LAYERS} WHERE job_id=? AND start_time=?", identities)
        conn.executemany(f"DELETE FROM {JOBS} WHERE job_id=? AND start_time=?", identities)


def read_records(conn, key, view="table", offset=0, limit=100, after_layer=0, live_metadata=None, live_row=None):
    if not conn.execute("SELECT 1 FROM job_history WHERE job_id=? AND start_time=?", key).fetchone():
        return None
    job = conn.execute(f"SELECT status,data FROM {JOBS} WHERE job_id=? AND start_time=?", key).fetchone()
    if job is None and live_metadata is None:
        return {"available": False, "reason": "not_recorded", "rows": [], "total": 0}
    status = job[0] if job else "recording"
    metadata = live_metadata if live_metadata is not None else unpack(job[1])
    high = metadata.get("max_layer", 0)
    diameters = metadata.get("diameters", {})
    low = after_layer if after_layer else offset + 1
    end = high if view == "series" else min(high, low + limit - 1)
    cursor = conn.execute(f"SELECT layer,data FROM {LAYERS} WHERE job_id=? AND start_time=? AND layer>=? AND layer<=? ORDER BY layer", (*key, low, end))
    grouped = {}
    width = max(1, math.ceil((end - low + 1) / MAX_POINTS)) if view == "series" else 1
    def source_rows():
        found = False
        for row in cursor:
            if live_row and row[0] == live_row["l"]:
                found = True
                yield live_row
            else:
                yield unpack(row[1])
        if live_row and not found and low <= live_row["l"] <= end:
            yield live_row

    bucket, bucket_number = [], None
    for data in source_rows():
        group = (data["l"] - low) // width
        if bucket and group != bucket_number:
            grouped[bucket_number] = (merge_rows(bucket) if len(bucket) > 1 else bucket[0], len(bucket))
            bucket = []
        bucket.append(data)
        bucket_number = group
    if bucket:
        grouped[bucket_number] = (merge_rows(bucket) if len(bucket) > 1 else bucket[0], len(bucket))
    buckets = []
    for group in range(math.ceil(max(0, end - low + 1) / width)):
        layer, last = low + group * width, min(end, low + (group + 1) * width - 1)
        empty = Accumulator(layer)
        empty.flags.add("unobserved_layer")
        data, count = grouped.get(group, (empty.data(), 0))
        data["l"], data["le"] = layer, last
        if count < last - layer + 1:
            data["f"] = sorted(set(data["f"]) | {"unobserved_layer"})
        buckets.append(data)
    summary = public_row(metadata.get("summary", Accumulator(0).data()), diameters)
    if status == "interrupted":
        metadata["flags"] = sorted(set(metadata.get("flags", [])) | {"interrupted"})
    return {"available": True, "schema_version": SCHEMA_VERSION, "approximate": True,
            "status": status, "metadata": {k: v for k, v in metadata.items() if k != "summary"},
            "summary": summary, "total": high, "rows": [public_row(row, diameters) for row in buckets]}


class LayerHistory:
    def __init__(self, config):
        self.server = config.get_server()
        self.db = self.server.lookup_component("database")
        self.history = self.server.lookup_component("history")
        if not hasattr(self.history, "register_delete_callback"):
            raise config.error("layer_history requires the matching history deletion hook")
        self.db.register_table(JobsDefinition())
        self.table = self.db.register_table(LayersDefinition())
        self.history.register_delete_callback(delete_records)
        self.klippy = self.server.lookup_component("klippy_apis")
        self.cache = {}
        self.recorder = None
        self.key = None
        self.filename = ""
        self.queue = deque()
        self.writer = None
        self.generation = 0
        self.failed = False
        self.subscribed = False
        self.diameters = {}
        self.server.register_event_handler("server:klippy_ready", self._ready)
        self.server.register_event_handler("server:klippy_disconnect", self._disconnected)
        self.server.register_event_handler("server:klippy_shutdown", self._disconnected)
        self.server.register_event_handler("history:history_changed", self._history_changed)
        self.server.register_endpoint("/server/layer_history/job", RequestType.GET, self._handle_job)

    async def component_init(self):
        def recover(conn):
            with conn:
                conn.execute(f"UPDATE {JOBS} SET status='interrupted' WHERE status='recording'")
        await self.db.queue_sql_callback(recover)

    async def _ready(self):
        if self.subscribed:
            return
        objects = {obj: ["temperature", "target"] for obj in CHANNELS.values()}
        objects.update({obj: ["speed"] for obj in FANS.values()})
        objects.update({"toolhead": ["position", "extruder"],
                        "motion_report": ["live_velocity", "live_extruder_velocity"],
                        "virtual_sdcard": ["file_position"], "print_stats": ["state", "filename"]})
        result = await self.klippy.subscribe_objects(objects, self._status_update, {})
        self.cache = result
        self.subscribed = True
        result = await self.klippy.query_objects({"configfile": ["settings"]}, {})
        settings = result.get("configfile", {}).get("settings", {})
        self.diameters = {tool: number(settings.get(obj, {}).get("filament_diameter"))
                          for tool, obj in (("t0", "extruder"), ("t1", "extruder1"))}
        if self.recorder:
            self.recorder.diameters.update(self.diameters)

    def _status_update(self, data, eventtime):
        for obj, values in data.items():
            self.cache.setdefault(obj, {}).update(values)
        if self.recorder is None or self.failed:
            return
        try:
            rows = self.recorder.step(self.cache, eventtime)
            if rows:
                self._schedule(rows, "recording")
        except Exception:
            self._failure("recording_failed")

    async def _history_changed(self, event):
        action = event.get("action")
        if action == "deleted":
            ids = event.get("deleted_jobs", [])
            if event.get("all") or self.key and f"{self.key[0]:06X}" in ids:
                self.generation += 1
                self.recorder = self.key = None
                self.queue.clear()
            return
        job = event.get("job", {})
        key = (int(job["job_id"], 16), float(job["start_time"]))
        if action == "added":
            await self._start(key, job)
        elif action == "finished" and self.key == key and self.recorder is None:
            # Indexing may still be running for a very short or cancelled job.
            self.generation += 1
            self.key = None
        elif action == "finished" and self.key == key and self.recorder:
            status = copy.deepcopy(self.cache)
            status.setdefault("print_stats", {})["state"] = {"completed": "complete"}.get(job["status"], job["status"])
            rows = self.recorder.finish(status, time.monotonic())
            self._schedule(rows, job["status"])
            self.recorder = self.key = None

    async def _start(self, key, job):
        self.generation += 1
        generation = self.generation
        self.recorder = None
        self.key, self.filename, self.failed = key, job["filename"], False
        manager = self.server.lookup_component("file_manager")
        root = Path(manager.get_directory("gcodes")).resolve()
        path = (root / job["filename"]).resolve()
        metadata = job.get("metadata") or {}
        try:
            if not path.is_relative_to(root):
                raise ValueError("gcode_outside_root")
            index = await asyncio.to_thread(LayerIndex.scan, path, metadata)
            if generation != self.generation or self.key != key:
                return
            self.recorder = Recorder(index, dict(self.diameters))
            self.recorder.step(self.cache, time.monotonic())
            self._schedule([], "recording")
        except Exception as exc:
            if generation == self.generation:
                data = {"schema_version": 1, "max_layer": 0, "expected_layers": metadata.get("layer_count", 0),
                        "flags": [str(exc)], "summary": Accumulator(0).data(), "diameters": self.diameters}
                await self.db.queue_sql_callback(lambda conn: write_snapshot(conn, key, "unavailable", data, []))
                logging.warning("Layer history unavailable for job %06X: %s", key[0], exc)

    def _schedule(self, rows, status):
        if self.recorder is None or self.key is None:
            return
        if len(self.queue) >= MAX_PENDING:
            self.queue.clear()
            self.recorder.flags.add("write_backlog")
            self.recorder.stopped = self.failed = True
            status = "incomplete"
            rows = []
        metadata = self.recorder.metadata()
        metadata["filename"] = self.filename
        self.queue.append((self.generation, self.key, status, metadata, rows))
        if self.writer is None or self.writer.done():
            self.writer = asyncio.create_task(self._drain())

    async def _drain(self):
        while self.queue:
            generation, key, status, metadata, rows = self.queue.popleft()
            try:
                await self.db.queue_sql_callback(lambda conn: write_snapshot(conn, key, status, metadata, rows))
            except Exception:
                self._failure("database_write_failed")
                self.queue.clear()
                return

    def _failure(self, reason):
        if not self.failed:
            logging.exception("Layer history stopped: %s", reason)
            self.server.add_warning("Layer history recording stopped: " + reason)
        self.failed = True
        if self.recorder:
            self.recorder.flags.add(reason)
            self.recorder.stopped = True

    def _disconnected(self):
        self.generation += 1
        self.subscribed = False
        if self.recorder:
            self.recorder.flags.add("disconnected")
            rows = [self.recorder.current.data()] if self.recorder.current else []
            self._schedule(rows, "interrupted")
        self.recorder = self.key = None
        self.cache = {}

    async def _handle_job(self, request):
        try:
            key = (int(request.get_str("uid"), 16), request.get_float("start_time"))
        except (ValueError, TypeError):
            raise self.server.error("Invalid layer history job identity", 400)
        view = request.get_str("view", "table")
        if view not in ("table", "series"):
            raise self.server.error("Invalid layer history view", 400)
        offset = max(0, request.get_int("offset", 0))
        limit = min(500, max(1, request.get_int("limit", 100)))
        after = max(0, request.get_int("after_layer", 0))
        generation = self.generation
        active = self.key == key and self.recorder is not None
        current = self.recorder.current.data() if active and self.recorder.current else None
        metadata = self.recorder.metadata() if active else None
        result = await self.db.queue_sql_callback(
            lambda conn: read_records(conn, key, view, offset, limit, after, metadata, current))
        if result is None or generation != self.generation and active:
            raise self.server.error("Print history was deleted or replaced", 404)
        if result.get("available") and active and metadata:
            result["metadata"] = {k: v for k, v in metadata.items() if k != "summary"}
            result["summary"] = public_row(metadata["summary"], metadata["diameters"])
            result["total"] = metadata["max_layer"]
            result["status"] = "incomplete" if self.failed else "recording"
        return result

    async def on_exit(self):
        self._disconnected()
        if self.writer:
            await self.writer


def load_component(config):
    return LayerHistory(config)
