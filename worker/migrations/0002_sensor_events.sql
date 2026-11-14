CREATE TABLE sensor_events (
  sensor TEXT NOT NULL,
  minute TEXT NOT NULL,
  country TEXT NOT NULL CHECK (country GLOB '[A-Z][A-Z]'),
  count INTEGER NOT NULL CHECK (count > 0),
  ingested_at TEXT NOT NULL,
  PRIMARY KEY (sensor, minute, country)
);

CREATE INDEX sensor_events_minute ON sensor_events (minute DESC);

CREATE TABLE sensor_status (
  sensor TEXT PRIMARY KEY,
  last_seen TEXT NOT NULL
);
